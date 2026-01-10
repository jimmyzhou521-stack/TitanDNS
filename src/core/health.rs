//! Upstream Health Tracking
//!
//! 追踪上游 DNS 服务器的健康状态：
//! - 成功/失败计数
//! - 平均响应时间
//! - 健康度评分

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 上游服务器健康状态追踪
#[derive(Debug)]
pub struct UpstreamHealth {
    /// 总查询次数
    pub queries: AtomicU64,
    /// 成功次数
    pub successes: AtomicU64,
    /// 失败次数
    pub failures: AtomicU64,
    /// 平均响应时间 (微秒)
    avg_response_time_us: AtomicU64,
    /// 最后成功时间
    last_success: Mutex<Option<Instant>>,
    /// 上游名称/地址
    pub name: String,
}

impl UpstreamHealth {
    /// 创建新的健康追踪器
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            queries: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            last_success: Mutex::new(None),
            name: name.into(),
        }
    }

    /// 记录成功的查询
    pub fn record_success(&self, response_time: Duration) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.successes.fetch_add(1, Ordering::Relaxed);
        
        // 更新平均响应时间 (简单移动平均)
        let new_time = response_time.as_micros() as u64;
        let old_avg = self.avg_response_time_us.load(Ordering::Relaxed);
        let successes = self.successes.load(Ordering::Relaxed);
        
        if successes <= 1 {
            self.avg_response_time_us.store(new_time, Ordering::Relaxed);
        } else {
            // 移动平均: new_avg = old_avg * 0.9 + new_time * 0.1
            let new_avg = (old_avg * 9 + new_time) / 10;
            self.avg_response_time_us.store(new_avg, Ordering::Relaxed);
        }
        
        // 更新最后成功时间
        if let Ok(mut last) = self.last_success.lock() {
            *last = Some(Instant::now());
        }
    }

    /// 记录失败的查询
    pub fn record_failure(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// 获取成功率 (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.queries.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0; // 无查询时假设健康
        }
        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    /// 获取平均响应时间
    pub fn avg_response_time(&self) -> Duration {
        Duration::from_micros(self.avg_response_time_us.load(Ordering::Relaxed))
    }

    /// 获取健康评分 (0.0 - 100.0)
    /// 综合考虑成功率和响应时间
    pub fn health_score(&self) -> f64 {
        let success_rate = self.success_rate();
        let avg_time_ms = self.avg_response_time().as_millis() as f64;
        
        // 基础分: 成功率 * 70
        let base_score = success_rate * 70.0;
        
        // 响应时间分: 最高 30 分，超过 500ms 为 0 分
        let time_score = if avg_time_ms < 50.0 {
            30.0  // <50ms 满分
        } else if avg_time_ms < 500.0 {
            30.0 * (1.0 - (avg_time_ms - 50.0) / 450.0)
        } else {
            0.0
        };
        
        base_score + time_score
    }

    /// 判断是否健康
    pub fn is_healthy(&self) -> bool {
        self.success_rate() > 0.5 && self.health_score() > 30.0
    }

    /// 获取统计快照
    pub fn stats(&self) -> HealthStats {
        HealthStats {
            queries: self.queries.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            avg_response_time_ms: self.avg_response_time().as_millis() as u64,
            success_rate: self.success_rate(),
            health_score: self.health_score(),
        }
    }

    /// 重置统计
    pub fn reset(&self) {
        self.queries.store(0, Ordering::Relaxed);
        self.successes.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.avg_response_time_us.store(0, Ordering::Relaxed);
    }
}

impl Default for UpstreamHealth {
    fn default() -> Self {
        Self::new("unknown")
    }
}

/// 健康统计快照
#[derive(Debug, Clone)]
pub struct HealthStats {
    pub queries: u64,
    pub successes: u64,
    pub failures: u64,
    pub avg_response_time_ms: u64,
    pub success_rate: f64,
    pub health_score: f64,
}

impl std::fmt::Display for HealthStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "queries={}, success_rate={:.1}%, avg_time={}ms, score={:.1}",
            self.queries,
            self.success_rate * 100.0,
            self.avg_response_time_ms,
            self.health_score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracking() {
        let health = UpstreamHealth::new("test");
        
        // 记录几次成功
        health.record_success(Duration::from_millis(50));
        health.record_success(Duration::from_millis(60));
        health.record_success(Duration::from_millis(40));
        
        assert_eq!(health.success_rate(), 1.0);
        assert!(health.is_healthy());
        
        // 记录一次失败
        health.record_failure();
        
        assert_eq!(health.success_rate(), 0.75);
        assert!(health.is_healthy());
    }

    #[test]
    fn test_health_score() {
        let health = UpstreamHealth::new("fast");
        
        // 快速响应
        for _ in 0..10 {
            health.record_success(Duration::from_millis(30));
        }
        
        let score = health.health_score();
        assert!(score > 90.0, "Fast upstream should have high score: {}", score);
    }
}
