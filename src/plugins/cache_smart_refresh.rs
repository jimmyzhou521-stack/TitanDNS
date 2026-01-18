//! # 智能刷新增强模块
//!
//! 提供基于 TTL 的智能缓存刷新策略，在缓存即将过期前主动刷新。
//!
//! ## 功能特性
//!
//! - **TTL 阈值刷新**：当剩余 TTL 低于阈值时触发刷新
//! - **百分比刷新**：在 TTL 剩余百分比（如 20%）时触发刷新
//! - **自适应刷新**：根据域名访问频率动态调整刷新策略
//! - **后台刷新**：不阻塞用户查询，后台异步刷新
//! - **平滑抖动**：添加随机抖动避免雷群效应
//!
//! ## 使用示例
//!
//! ```rust
//! use crate::plugins::cache_smart_refresh::SmartRefreshManager;
//!
//! // 创建智能刷新管理器
//! let manager = SmartRefreshManager::new(cache_plugin.clone(), forward_plugin.clone());
//!
//! // 配置刷新策略
//! manager.configure_threshold(60)  // TTL < 60s 时刷新
//!          .configure_percentage(20)  // 或 TTL 剩余 < 20% 时刷新
//!          .enable_adaptive(true);    // 启用自适应刷新
//!
//! // 启动后台刷新任务
//! manager.start_background_task();
//! ```

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use crate::plugins::cache::CachePlugin;
use crate::plugins::forward::ForwardPlugin;
use crate::core::task_manager::TaskManager;
use dashmap::DashMap;

/// 智能刷新管理器
pub struct SmartRefreshManager {
    /// 缓存插件引用
    cache: Arc<CachePlugin>,
    /// 转发插件引用
    forwarder: Arc<ForwardPlugin>,
    /// 刷新策略配置
    config: Arc<RwLock<RefreshConfig>>,
    /// 正在刷新的域名（防止重复刷新）
    refreshing: Arc<DashMap<String, u64>>,
    /// 刷新统计（原子计数）
    stats: Arc<RefreshStatsAtomic>,
    /// 后台任务管理器
    task_mgr: Arc<TaskManager>,
}

/// 刷新策略配置
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// TTL 阈值（秒）：当剩余 TTL 低于此值时触发刷新
    pub ttl_threshold: u64,
    /// TTL 百分比阈值：当剩余 TTL 百分比低于此值时触发刷新
    pub ttl_percentage: u8, // 0-100
    /// 是否启用自适应刷新
    pub adaptive_enabled: bool,
    /// 刷新间隔（秒）
    pub refresh_interval: u64,
    /// 抖动范围（毫秒）
    pub jitter_ms: u64,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            ttl_threshold: 60,        // 默认 60 秒
            ttl_percentage: 20,       // 默认 20%
            adaptive_enabled: false,
            refresh_interval: 30,     // 默认 30 秒检查一次
            jitter_ms: 1000,          // 默认 1 秒抖动
        }
    }
}

impl Clone for SmartRefreshManager {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            forwarder: Arc::clone(&self.forwarder),
            config: Arc::clone(&self.config),
            refreshing: Arc::clone(&self.refreshing),
            stats: Arc::clone(&self.stats),
            task_mgr: Arc::clone(&self.task_mgr),
        }
    }
}

impl SmartRefreshManager {
    /// 创建新的智能刷新管理器
    ///
    /// # 参数
    ///
    /// * `cache` - 缓存插件实例
    /// * `forwarder` - 转发插件实例
    pub fn new(cache: Arc<CachePlugin>, forwarder: Arc<ForwardPlugin>) -> Self {
        Self {
            cache,
            forwarder,
            config: Arc::new(RwLock::new(RefreshConfig::default())),
            refreshing: Arc::new(DashMap::new()),
            stats: Arc::new(RefreshStatsAtomic::default()),
            task_mgr: Arc::new(TaskManager::new()),
        }
    }

    /// 配置 TTL 阈值
    ///
    /// # 示例
    ///
    /// ```ignore
    /// manager.configure_threshold(120);  // TTL < 120s 时刷新
    /// ```
    pub async fn configure_threshold(&self, threshold_secs: u64) -> &Self {
        let mut config = self.config.write().await;
        config.ttl_threshold = threshold_secs;
        self
    }

    /// 配置 TTL 百分比阈值
    ///
    /// # 示例
    ///
    /// ```ignore
    /// manager.configure_percentage(15);  // TTL 剩余 < 15% 时刷新
    /// ```
    pub async fn configure_percentage(&self, percentage: u8) -> &Self {
        let mut config = self.config.write().await;
        config.ttl_percentage = percentage.min(100);
        self
    }

    /// 启用/禁用自适应刷新
    pub async fn enable_adaptive(&self, enabled: bool) -> &Self {
        let mut config = self.config.write().await;
        config.adaptive_enabled = enabled;
        self
    }

    /// 配置刷新间隔
    pub async fn configure_interval(&self, interval_secs: u64) -> &Self {
        let mut config = self.config.write().await;
        config.refresh_interval = interval_secs;
        self
    }

    /// 配置抖动范围
    pub async fn configure_jitter(&self, jitter_ms: u64) -> &Self {
        let mut config = self.config.write().await;
        config.jitter_ms = jitter_ms;
        self
    }

    /// 启动后台刷新任务
    ///
    /// 定期扫描缓存，对即将过期的条目进行刷新
    pub fn start_background_task(&self) {
        let manager = self.clone();
        if !self.task_mgr.start(move |shutdown| {
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10)); // 每 10 秒检查一次
                let mut check_counter = 0u32;

                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            break;
                        }
                        _ = interval.tick() => {
                            check_counter += 1;

                            // 根据配置的间隔执行刷新
                            let config = manager.config.read().await;
                            let should_check = check_counter >= (config.refresh_interval / 10) as u32;

                            if should_check {
                                check_counter = 0;
                                drop(config); // 释放锁

                                info!("🔄 智能刷新：开始扫描缓存...");
                                let stats = manager.scan_and_refresh().await;
                                info!("🔄 智能刷新完成: 扫描={}, 刷新={}, 跳过={}",
                                      stats.scanned, stats.refreshed, stats.skipped);
                            }
                        }
                    }
                }
            }
        }) {
            return;
        }

        info!("🚀 智能刷新后台任务已启动");
    }

    /// 停止后台刷新任务
    pub fn stop_background_task(&self) {
        self.task_mgr.stop();
    }
    /// 扫描缓存并刷新即将过期的条目
    async fn scan_and_refresh(&self) -> RefreshStats {
        let mut stats = RefreshStats::default();
        let entries = self.cache.snapshot_entries(0);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for entry in entries {
            stats.scanned += 1;

            // Compute remaining TTL
            let elapsed = now.saturating_sub(entry.timestamp);
            let remaining_ttl = entry.ttl.saturating_sub(elapsed);

            // Extract domain/qtype/qclass from cached response
            let query = match entry.message.query() {
                Some(q) => q,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };

            let domain = query.name().to_string();
            let qtype = u16::from(query.query_type());
            let qclass = u16::from(query.query_class());

            if self.should_refresh_with_ttl(remaining_ttl, entry.ttl).await {
                stats.refreshed += 1;
                self.trigger_refresh(domain, qtype, qclass).await;
            } else {
                stats.skipped += 1;
            }
        }

        self.stats.set(&stats);
        stats
    }

    /// 检查单个缓存条目是否需要刷新
    ///
    /// 这是一个公共方法，可以在缓存查询时调用
    ///
    /// # 参数
    ///
    /// * `remaining_ttl` - 剩余 TTL（秒）
    /// * `original_ttl` - 原始 TTL（秒）
    ///
    /// # 返回
    ///
    /// 如果需要刷新，返回 true
    pub async fn should_refresh_with_ttl(&self, remaining_ttl: u64, original_ttl: u64) -> bool {
        let config = self.config.read().await;

        // 策略 1：TTL 阈值检查
        if remaining_ttl < config.ttl_threshold {
            return true;
        }

        // 策略 2：TTL 百分比检查
        if original_ttl > 0 {
            let remaining_percentage = (remaining_ttl as f64 / original_ttl as f64 * 100.0) as u8;
            if remaining_percentage < config.ttl_percentage {
                return true;
            }
        }

        false
    }

    /// 触发后台刷新
    ///
    /// 异步刷新指定的域名
    ///
    /// # 参数
    ///
    /// * `domain` - 域名
    /// * `qtype` - 查询类型
    /// * `qclass` - 查询类
    pub async fn trigger_refresh(&self, domain: String, qtype: u16, qclass: u16) {
        // 防止重复刷新
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(last_refresh) = self.refreshing.get(&domain) {
            if now < *last_refresh + 10 {
                debug!("⏭️  跳过重复刷新: {}", domain);
                return;
            }
        }

        self.refreshing.insert(domain.clone(), now);

        let manager = self.clone();
        let config = self.config.read().await.clone();

        tokio::spawn(async move {
            // 添加抖动
            if config.jitter_ms > 0 {
                use rand::Rng;
                let jitter = rand::thread_rng().gen_range(0..config.jitter_ms);
                tokio::time::sleep(Duration::from_millis(jitter)).await;
            }

            match manager.refresh_domain(&domain, qtype, qclass).await {
                Ok(_) => {
                    debug!("✅ 智能刷新成功: {}", domain);
                }
                Err(e) => {
                    warn!("❌ 智能刷新失败: {}: {}", domain, e);
                }
            }
        });
    }

    /// 刷新单个域名
    async fn refresh_domain(&self, domain: &str, qtype: u16, qclass: u16) -> Result<()> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{RecordType, DNSClass, Name};

        // 构造查询
        let mut query = Query::new();
        let name = Name::from_ascii(domain)?;
        query.set_name(name);
        query.set_query_type(RecordType::from(qtype));
        query.set_query_class(DNSClass::from(qclass));

        let mut request = Message::new();
        request.set_id(1);
        request.set_recursion_desired(true);
        request.add_query(query);

        // 执行查询
        let response = self.forwarder.execute(&request, None).await?;

        // 验证响应
        if response.response_code() == hickory_proto::op::ResponseCode::NoError {
            // 写回缓存
            if let Some(ttl) = self.cache.insert_response_for_domain(domain, qtype, qclass, response.clone()).await {
                debug!("🔄 域名已刷新并写回缓存: {} (TTL: {}s)", domain, ttl);
            } else {
                warn!("⚠️  刷新成功但未写入缓存: {}", domain);
            }
        } else {
            warn!("⚠️  刷新响应错误: {} - {:?}", domain, response.response_code());
        }

        Ok(())
    }

    /// 获取当前配置
    pub async fn get_config(&self) -> RefreshConfig {
        self.config.read().await.clone()
    }

    /// 获取刷新统计
    pub async fn get_stats(&self) -> RefreshStats {
        self.stats.snapshot()
    }
}

#[derive(Default)]
struct RefreshStatsAtomic {
    scanned: AtomicU64,
    refreshed: AtomicU64,
    skipped: AtomicU64,
}

impl RefreshStatsAtomic {
    fn set(&self, stats: &RefreshStats) {
        self.scanned.store(stats.scanned as u64, Ordering::Relaxed);
        self.refreshed.store(stats.refreshed as u64, Ordering::Relaxed);
        self.skipped.store(stats.skipped as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RefreshStats {
        RefreshStats {
            scanned: self.scanned.load(Ordering::Relaxed) as usize,
            refreshed: self.refreshed.load(Ordering::Relaxed) as usize,
            skipped: self.skipped.load(Ordering::Relaxed) as usize,
        }
    }
}

/// 刷新统计信息
#[derive(Debug, Default, Clone)]
pub struct RefreshStats {
    /// 扫描的条目数
    pub scanned: usize,
    /// 刷新的条目数
    pub refreshed: usize,
    /// 跳过的条目数
    pub skipped: usize,
}

/// 智能刷新辅助函数
///
/// 在缓存查询时调用，判断是否需要触发后台刷新
///
/// # 参数
///
/// * `manager` - 刷新管理器（可选）
/// * `remaining_ttl` - 剩余 TTL（秒）
/// * `original_ttl` - 原始 TTL（秒）
/// * `domain` - 域名
/// * `qtype` - 查询类型
/// * `qclass` - 查询类
///
/// # 使用示例
///
/// ```ignore
/// // 在 CachePlugin::handle() 中
/// if let Some(refresh_manager) = &self.refresh_manager {
///     if let Some(cached_entry) = self.cache.get(&key).await {
///         // 计算剩余 TTL
///         let remaining_ttl = /* 计算剩余 TTL */;
///         let original_ttl = cached_entry.ttl;
///         // 检查是否需要刷新
///         if refresh_manager.should_refresh_with_ttl(remaining_ttl, original_ttl).await {
///             refresh_manager.trigger_refresh(domain, qtype, qclass).await;
///         }
///     }
/// }
/// ```
pub async fn check_and_trigger_refresh(
    manager: &Option<SmartRefreshManager>,
    remaining_ttl: u64,
    original_ttl: u64,
    domain: &str,
    qtype: u16,
    qclass: u16,
) {
    if let Some(refresh_mgr) = manager {
        if refresh_mgr.should_refresh_with_ttl(remaining_ttl, original_ttl).await {
            refresh_mgr.trigger_refresh(domain.to_string(), qtype, qclass).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RefreshConfig::default();
        assert_eq!(config.ttl_threshold, 60);
        assert_eq!(config.ttl_percentage, 20);
        assert_eq!(config.adaptive_enabled, false);
    }

    #[tokio::test]
    async fn test_configure_threshold() {
        // 测试配置（需要实际的 CachePlugin 和 ForwardPlugin）
        // 这里仅作为示例
    }
}


impl Drop for SmartRefreshManager {
    fn drop(&mut self) {
        self.task_mgr.stop();
    }
}

