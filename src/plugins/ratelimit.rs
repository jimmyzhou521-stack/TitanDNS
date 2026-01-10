//! Rate Limiting Plugin
//!
//! QPS 限流防护，防止 DoS 攻击

use anyhow::Result;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// 限流记录
#[derive(Debug)]
struct RateLimitEntry {
    /// 当前窗口查询数
    count: u32,
    /// 窗口起始时间
    window_start: Instant,
}

/// 限流插件
#[derive(Debug)]
pub struct RateLimitPlugin {
    pub name: String,
    /// 每个窗口最大查询数
    pub max_queries: u32,
    /// 时间窗口（秒）
    pub window_secs: u64,
    /// IP 限流表
    limits: Arc<DashMap<IpAddr, RateLimitEntry>>,
}

impl RateLimitPlugin {
    pub fn new(max_queries: u32, window_secs: u64) -> Self {
        let plugin = Self {
            name: "rate_limit".to_string(),
            max_queries,
            window_secs,
            limits: Arc::new(DashMap::new()),
        };
        
        // [FIX] Start background cleanup task
        plugin.start_cleanup_task();
        
        plugin
    }

    /// [NEW] Start background cleanup task (runs every 2x window duration)
    fn start_cleanup_task(&self) {
        let limits = self.limits.clone();
        let window_secs = self.window_secs;
        
        tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(window_secs * 2);
            loop {
                tokio::time::sleep(cleanup_interval).await;
                
                let now = Instant::now();
                let window_duration = Duration::from_secs(window_secs);
                let before = limits.len();
                
                limits.retain(|_, entry| {
                    now.duration_since(entry.window_start) < window_duration * 2
                });
                
                let after = limits.len();
                if before > after {
                    tracing::debug!("🧹 RateLimit cleanup: {} -> {} entries", before, after);
                }
            }
        });
    }

    /// 检查是否应该限流
    fn should_limit(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.window_secs);

        let mut should_limit = false;

        self.limits
            .entry(client_ip)
            .and_modify(|entry| {
                // 检查是否需要重置窗口
                if now.duration_since(entry.window_start) >= window_duration {
                    entry.count = 1;
                    entry.window_start = now;
                } else {
                    entry.count += 1;
                    if entry.count > self.max_queries {
                        should_limit = true;
                    }
                }
            })
            .or_insert(RateLimitEntry {
                count: 1,
                window_start: now,
            });

        should_limit
    }

    /// 清理过期条目
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.window_secs);

        self.limits.retain(|_, entry| {
            now.duration_since(entry.window_start) < window_duration * 2
        });
    }

    /// 获取当前限流统计
    pub fn stats(&self) -> (usize, u64) {
        let total_entries = self.limits.len();
        let total_queries: u64 = self.limits.iter().map(|e| e.value().count as u64).sum();
        (total_entries, total_queries)
    }
}

impl Plugin for RateLimitPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // 从 context 获取客户端 IP
        let client_ip = ctx.client_addr.ip();

        if self.should_limit(client_ip) {
            warn!("🚫 Rate limit exceeded for IP: {} ({} queries/{}s)", 
                  client_ip, self.max_queries, self.window_secs);

            // 创建 REFUSED 响应
            let mut response = hickory_proto::op::Message::new();
            response.set_id(ctx.request.id());
            response.set_message_type(hickory_proto::op::MessageType::Response);
            response.set_response_code(hickory_proto::op::ResponseCode::Refused);

            ctx.set_response(response, true);
        } else {
            debug!("✅ Rate limit check passed for IP: {}", client_ip);
        }

        Ok(())
    }
}

impl Clone for RateLimitPlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            max_queries: self.max_queries,
            window_secs: self.window_secs,
            limits: self.limits.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_within_limit() {
        let limiter = RateLimitPlugin::new(5, 60);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert!(!limiter.should_limit(ip));
        }
    }

    #[test]
    fn test_rate_limit_exceeds() {
        let limiter = RateLimitPlugin::new(3, 60);
        let ip: IpAddr = "192.168.1.2".parse().unwrap();

        // 前 3 次应该通过
        for _ in 0..3 {
            assert!(!limiter.should_limit(ip));
        }

        // 第 4 次应该被限流
        assert!(limiter.should_limit(ip));
    }

    #[test]
    fn test_independent_ips() {
        let limiter = RateLimitPlugin::new(2, 60);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // 每个 IP 独立限流
        assert!(!limiter.should_limit(ip1));
        assert!(!limiter.should_limit(ip2));
        assert!(!limiter.should_limit(ip1));
        assert!(!limiter.should_limit(ip2));

        // 两个都达到限制
        assert!(limiter.should_limit(ip1));
        assert!(limiter.should_limit(ip2));
    }
}
