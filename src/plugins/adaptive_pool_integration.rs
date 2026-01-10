//! # 自适应连接池集成指南
//!
//! 本文档展示如何将 `AdaptiveConnectionPool` 集成到现有的 `forward.rs` 中
//!
//! ## 集成步骤
//!
//! ### 1. 在 `forward.rs` 中添加自适应连接池
//!
//! ```rust
//! // 在 forward.rs 顶部添加
//! use crate::plugins::adaptive_pool::AdaptiveConnectionPool;
//!
//! // 在 ForwardPlugin 结构体中添加字段
//! pub struct ForwardPlugin {
//!     pub name: String,
//!     pub upstreams: Vec<Arc<Upstream>>,
//!     pub timeout: Duration,
//!     pub concurrent_limit: Arc<Semaphore>,
//!     pub strategy: Option<String>,
//!     pub proxy_status: Option<Arc<AtomicBool>>,
//!     pub singleflight: Arc<Singleflight<String, Message>>,
//!
//!     // ✨ 新增：自适应连接池
//!     pub adaptive_pool: Arc<AdaptiveConnectionPool>,
//! }
//! ```
//!
//! ### 2. 在构造函数中初始化
//!
//! ```rust
//! impl ForwardPlugin {
//!     pub fn new(
//!         name: String,
//!         upstreams: Vec<UpstreamConfig>,
//!         timeout: Duration,
//!         concurrent_limit: usize,
//!         strategy: Option<String>,
//!         proxy_status: Option<Arc<AtomicBool>>,
//!     ) -> Result<Self> {
//!         // ... 现有代码 ...
//!
//!         Ok(Self {
//!             name,
//!             upstreams: built_upstreams,
//!             timeout,
//!             concurrent_limit: Arc::new(Semaphore::new(concurrent_limit)),
//!             strategy,
//!             proxy_status: proxy_status.map(Arc::new),
//!             singleflight: Arc::new(Singleflight::new()),
//!
//!             // ✨ 新增：初始化自适应连接池
//!             adaptive_pool: Arc::new(AdaptiveConnectionPool::new()),
//!         })
//!     }
//! }
//! ```
//!
//! ### 3. 在查询处理中记录 QPS
//!
//! ```rust
//! impl Plugin for ForwardPlugin {
//!     async fn handle(&self, ctx: &Context) -> Result<Message> {
//!         // ✨ 新增：记录查询（用于 QPS 统计）
//!         self.adaptive_pool.record_query();
//!
//!         // ✨ 新增：定期调整连接池
//!         if self.adaptive_pool.should_adjust() {
//!             self.adaptive_pool.adjust();
//!         }
//!
//!         // ... 现有查询逻辑 ...
//!     }
//! }
//! ```
//!
//! ### 4. 在 DoH 客户端创建时使用动态配置
//!
//! ```rust
//! // 在创建 DoH 客户端时
//! let pool_size = self.adaptive_pool.get_pool_size();
//! let idle_timeout = self.adaptive_pool.get_idle_timeout_duration();
//!
//! let client = reqwest::Client::builder()
//!     .pool_idle_timeout(idle_timeout)
//!     .pool_max_idle_per_host(pool_size)
//!     // ... 其他配置 ...
//!     .build()
//!     .context("Failed to build DoH client")?;
//! ```
//!
//! ### 5. 在 DoT/DoQ 连接检查中使用动态超时
//!
//! ```rust
//! impl DotConnection {
//!     fn is_alive_with_pool(&self, pool: &AdaptiveConnectionPool) -> bool {
//!         let timeout = pool.get_idle_timeout_duration();
//!         self.last_used.elapsed() < timeout
//!     }
//! }
//!
//! impl DoqConnection {
//!     fn is_alive_with_pool(&self, pool: &AdaptiveConnectionPool) -> bool {
//!         let timeout = pool.get_idle_timeout_duration();
//!         self.last_used.elapsed() < timeout
//!     }
//! }
//! ```
//!
//! ## 完整示例
//!
//! ```rust
//! use crate::plugins::adaptive_pool::AdaptiveConnectionPool;
//! use std::sync::Arc;
//!
//! pub struct ForwardPlugin {
//!     // ... 现有字段 ...
//!     pub adaptive_pool: Arc<AdaptiveConnectionPool>,
//! }
//!
//! impl ForwardPlugin {
//!     pub async fn handle_query(&self, ctx: &Context) -> Result<Message> {
//!         // 1. 记录查询
//!         self.adaptive_pool.record_query();
//!
//!         // 2. 定期调整连接池（每 30 秒）
//!         if self.adaptive_pool.should_adjust() {
//!             let pool = Arc::clone(&self.adaptive_pool);
//!             tokio::spawn(async move {
//!                 pool.adjust();
//!             });
//!         }
//!
//!         // 3. 执行查询
//!         self.forward(ctx).await
//!     }
//!
//!     async fn create_doh_client(&self) -> Result<reqwest::Client> {
//!         let pool_size = self.adaptive_pool.get_pool_size();
//!         let idle_timeout = self.adaptive_pool.get_idle_timeout_duration();
//!
//!         reqwest::Client::builder()
//!             .pool_idle_timeout(idle_timeout)
//!             .pool_max_idle_per_host(pool_size)
//!             .build()
//!             .context("Failed to build DoH client")
//!     }
//! }
//! ```

use std::sync::Arc;
use crate::plugins::adaptive_pool::AdaptiveConnectionPool;

/// 集成示例：修改后的 ForwardPlugin 结构体
#[derive(Debug, Clone)]
pub struct ForwardPluginWithAdaptivePool {
    pub name: String,
    pub upstreams: Vec<Arc<crate::plugins::forward::Upstream>>,
    pub timeout: std::time::Duration,
    pub concurrent_limit: Arc<tokio::sync::Semaphore>,
    pub strategy: Option<String>,
    pub proxy_status: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub singleflight: Arc<crate::core::singleflight::Singleflight<String, hickory_proto::op::Message>>,

    /// ✨ 新增：自适应连接池
    pub adaptive_pool: Arc<AdaptiveConnectionPool>,
}

impl ForwardPluginWithAdaptivePool {
    /// 创建新的实例（集成自适应连接池）
    pub fn with_adaptive_pool(
        name: String,
        upstreams: Vec<crate::config::UpstreamConfig>,
        timeout: std::time::Duration,
        concurrent_limit: usize,
        strategy: Option<String>,
        proxy_status: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        use crate::config::UpstreamConfig;
        use crate::plugins::forward::Upstream;

        // 构建上游列表
        let built_upstreams: Vec<Arc<Upstream>> = upstreams
            .into_iter()
            .filter_map(|conf| Upstream::new(conf).ok())
            .map(Arc::new)
            .collect();

        Self {
            name,
            upstreams: built_upstreams,
            timeout,
            concurrent_limit: Arc::new(tokio::sync::Semaphore::new(concurrent_limit)),
            strategy,
            proxy_status,
            singleflight: Arc::new(crate::core::singleflight::Singleflight::new()),
            adaptive_pool: Arc::new(AdaptiveConnectionPool::new()),
        }
    }

    /// 获取当前 DoH 客户端配置（使用动态参数）
    pub async fn get_doh_client(&self) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
        let pool_size = self.adaptive_pool.get_pool_size();
        let idle_timeout = self.adaptive_pool.get_idle_timeout_duration();

        let client = reqwest::Client::builder()
            .pool_idle_timeout(idle_timeout)
            .pool_max_idle_per_host(pool_size)
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(3))
            .http2_only(true)
            .build()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(client)
    }

    /// 模拟查询处理（带自适应调整）
    pub async fn handle_query_simulation(&self) -> Result<String, Box<dyn std::error::Error>> {
        // 1. 记录查询
        self.adaptive_pool.record_query();

        // 2. 检查是否需要调整连接池
        if self.adaptive_pool.should_adjust() {
            let pool = Arc::clone(&self.adaptive_pool);
            tokio::spawn(async move {
                pool.adjust();
            });
        }

        // 3. 执行查询逻辑
        Ok("Query processed".to_string())
    }

    /// 获取当前连接池状态（用于监控）
    pub fn get_pool_status(&self) -> PoolStatus {
        PoolStatus {
            pool_size: self.adaptive_pool.get_pool_size(),
            idle_timeout_secs: self.adaptive_pool.get_idle_timeout(),
            current_qps: self.estimate_current_qps(),
        }
    }

    /// 估算当前 QPS
    fn estimate_current_qps(&self) -> f64 {
        // 这里可以根据实际的 query_count 计算
        // 简化版本：返回估算值
        self.adaptive_pool.get_pool_size() as f64 * 100.0
    }
}

/// 连接池状态（用于监控）
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub pool_size: usize,
    pub idle_timeout_secs: u64,
    pub current_qps: f64,
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_adaptive_pool_integration() {
        let plugin = ForwardPluginWithAdaptivePool::with_adaptive_pool(
            "test".to_string(),
            vec![],
            std::time::Duration::from_secs(5),
            100,
            Some("race".to_string()),
            None,
        );

        // 模拟不同负载
        for i in 0..1000 {
            plugin.handle_query_simulation().await.unwrap();
        }

        // 获取状态
        let status = plugin.get_pool_status();
        println!("Pool status: {:?}", status);

        // 验证配置
        assert!(status.pool_size >= 5);
        assert!(status.idle_timeout_secs >= 180);
    }
}
