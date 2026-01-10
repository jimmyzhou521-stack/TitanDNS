//! # 自适应连接池管理器
//!
//! 根据实时负载（QPS）动态调整连接池参数
//!
//! ## 功能特性
//!
//! - **动态调整连接池大小**：根据 QPS 自动增加/减少连接
//! - **动态调整空闲超时**：高负载时延长超时，低负载时缩短超时
//! - **负载感知**：基于实际 QPS 进行决策
//! - **平滑过渡**：避免频繁调整导致抖动
//!
//! ## 调整策略
//!
//! | QPS 范围 | 连接池大小 | 空闲超时 | 说明 |
//! |----------|-----------|----------|------|
//! | < 1000   | 5         | 180s     | 低负载模式 |
//! | 1000-3000 | 10        | 300s     | 正常模式 |
//! | 3000-5000 | 15        | 600s     | 高负载模式 |
//! | > 5000   | 20        | 900s     | 极限模式 |
//!
//! ## 使用示例
//!
//! ```rust
//! use adaptive_pool::AdaptiveConnectionPool;
//!
//! let pool = AdaptiveConnectionPool::new();
//! loop {
//!     // 更新 QPS 统计
//!     pool.record_query();
//!
//!     // 每 10 秒调整一次
//!     if pool.should_adjust() {
//!         pool.adjust();
//!     }
//! }
//! ```

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn, debug};

/// 连接池配置
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// 连接池大小
    pub pool_size: usize,
    /// 空闲连接超时时间（秒）
    pub idle_timeout: u64,
}

impl PoolConfig {
    /// DoH 连接池配置
    pub fn for_doh() -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(10)
    }

    /// DoT 连接池配置
    pub fn for_dot_max_connections() -> usize {
        10
    }

    /// DoT 空闲超时配置
    pub fn for_dot_idle_timeout() -> Duration {
        Duration::from_secs(300)
    }
}

/// 自适应连接池管理器
#[derive(Debug)]
pub struct AdaptiveConnectionPool {
    /// 查询计数器（用于计算 QPS）
    query_count: AtomicU64,
    /// 上次调整时间
    last_adjust: AtomicU64,
    /// 当前连接池大小
    current_pool_size: AtomicUsize,
    /// 当前空闲超时（秒）
    current_idle_timeout: AtomicU64,
    /// 调整间隔（秒）
    adjust_interval: u64,
}

impl AdaptiveConnectionPool {
    /// 创建新的自适应连接池
    ///
    /// # 参数
    ///
    /// - `adjust_interval`: 调整间隔（秒），默认 30 秒
    ///
    /// # 示例
    ///
    /// ```rust
    /// let pool = AdaptiveConnectionPool::new();
    /// let pool = AdaptiveConnectionPool::with_interval(60); // 60 秒调整一次
    /// ```
    pub fn new() -> Self {
        Self::with_interval(30)
    }

    /// 指定调整间隔
    pub fn with_interval(adjust_interval: u64) -> Self {
        Self {
            query_count: AtomicU64::new(0),
            last_adjust: AtomicU64::new(0),
            current_pool_size: AtomicUsize::new(10), // 默认 10
            current_idle_timeout: AtomicU64::new(300), // 默认 300 秒
            adjust_interval,
        }
    }

    /// 记录一次查询（调用此方法更新 QPS 统计）
    #[inline]
    pub fn record_query(&self) {
        self.query_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 检查是否应该调整连接池
    pub fn should_adjust(&self) -> bool {
        let now = Instant::now()
            .duration_since(Instant::now())
            .as_secs() as u64;

        let last_adjust = self.last_adjust.load(Ordering::Relaxed);

        // 检查是否到达调整间隔
        now.saturating_sub(last_adjust) >= self.adjust_interval
    }

    /// 执行连接池调整
    ///
    /// 根据最近的 QPS 自动调整连接池参数
    pub fn adjust(&self) {
        // 1. 计算当前 QPS
        let qps = self.calculate_qps();

        // 2. 根据负载确定目标配置
        let (target_pool_size, target_idle_timeout) = self.get_target_config(qps);

        // 3. 应用新配置
        self.apply_config(qps, target_pool_size, target_idle_timeout);

        // 4. 重置计数器并更新时间戳
        self.query_count.store(0, Ordering::Relaxed);
        self.last_adjust.store(
            Instant::now()
                .duration_since(Instant::now())
                .as_secs() as u64,
            Ordering::Relaxed
        );
    }

    /// 计算 QPS
    fn calculate_qps(&self) -> f64 {
        let query_count = self.query_count.load(Ordering::Relaxed);
        let elapsed = self.get_elapsed_seconds();

        if elapsed > 0 {
            query_count as f64 / elapsed as f64
        } else {
            0.0
        }
    }

    /// 获取经过的秒数
    fn get_elapsed_seconds(&self) -> u64 {
        let now = Instant::now()
            .duration_since(Instant::now())
            .as_secs() as u64;
        let last_adjust = self.last_adjust.load(Ordering::Relaxed);

        now.saturating_sub(last_adjust).max(1) // 至少 1 秒
    }

    /// 根据 QPS 获取目标配置
    fn get_target_config(&self, qps: f64) -> (usize, u64) {
        match qps {
            // 低负载模式
            qps if qps < 1000.0 => {
                debug!("低负载模式: QPS={}", qps);
                (5, 180) // 5 个连接，3 分钟超时
            }

            // 正常模式
            qps if qps < 3000.0 => {
                debug!("正常负载模式: QPS={}", qps);
                (10, 300) // 10 个连接，5 分钟超时
            }

            // 高负载模式
            qps if qps < 5000.0 => {
                info!("高负载模式: QPS={}", qps);
                (15, 600) // 15 个连接，10 分钟超时
            }

            // 极限模式
            qps => {
                warn!("极限负载模式: QPS={}", qps);
                (20, 900) // 20 个连接，15 分钟超时
            }
        }
    }

    /// 应用新配置
    fn apply_config(&self, qps: f64, pool_size: usize, idle_timeout: u64) {
        let old_pool_size = self.current_pool_size.load(Ordering::Relaxed);
        let old_idle_timeout = self.current_idle_timeout.load(Ordering::Relaxed);

        // 检查是否需要调整
        if old_pool_size == pool_size && old_idle_timeout == idle_timeout {
            debug!("无需调整: QPS={}, pool_size={}, idle_timeout={}s",
                   qps, pool_size, idle_timeout);
            return;
        }

        // 更新配置
        self.current_pool_size.store(pool_size, Ordering::Relaxed);
        self.current_idle_timeout.store(idle_timeout, Ordering::Relaxed);

        // 记录调整日志
        info!(
            "🔄 连接池已调整: QPS={:.1}, pool_size: {} → {}, idle_timeout: {}s → {}s",
            qps, old_pool_size, pool_size, old_idle_timeout, idle_timeout
        );
    }

    /// 获取当前连接池大小
    pub fn get_pool_size(&self) -> usize {
        self.current_pool_size.load(Ordering::Relaxed)
    }

    /// 获取当前空闲超时（秒）
    pub fn get_idle_timeout(&self) -> u64 {
        self.current_idle_timeout.load(Ordering::Relaxed)
    }

    /// 获取当前空闲超时（Duration）
    pub fn get_idle_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.get_idle_timeout())
    }
}

impl Default for AdaptiveConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_load() {
        let pool = AdaptiveConnectionPool::new();

        // 模拟 500 QPS（低负载）
        for _ in 0..500 {
            pool.record_query();
        }

        pool.adjust();

        assert_eq!(pool.get_pool_size(), 5);
        assert_eq!(pool.get_idle_timeout(), 180);
    }

    #[test]
    fn test_normal_load() {
        let pool = AdaptiveConnectionPool::new();

        // 模拟 2000 QPS（正常负载）
        for _ in 0..2000 {
            pool.record_query();
        }

        pool.adjust();

        assert_eq!(pool.get_pool_size(), 10);
        assert_eq!(pool.get_idle_timeout(), 300);
    }

    #[test]
    fn test_high_load() {
        let pool = AdaptiveConnectionPool::new();

        // 模拟 4000 QPS（高负载）
        for _ in 0..4000 {
            pool.record_query();
        }

        pool.adjust();

        assert_eq!(pool.get_pool_size(), 15);
        assert_eq!(pool.get_idle_timeout(), 600);
    }

    #[test]
    fn test_extreme_load() {
        let pool = AdaptiveConnectionPool::new();

        // 模拟 6000 QPS（极限负载）
        for _ in 0..6000 {
            pool.record_query();
        }

        pool.adjust();

        assert_eq!(pool.get_pool_size(), 20);
        assert_eq!(pool.get_idle_timeout(), 900);
    }
}
