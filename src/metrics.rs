// Prometheus Metrics Export
// Provides detailed metrics for monitoring and observability

#![allow(dead_code)] // Framework implementation

use axum::{
    routing::get,
    Router,
    response::IntoResponse,
    http::StatusCode,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;

/// Global metrics collector
pub struct MetricsCollector {
    // Query metrics
    pub total_queries: AtomicU64,
    pub total_responses: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_stale_hits: AtomicU64,    // LazyCache 过期命中
    pub cache_refreshes: AtomicU64,     // 后台刷新次数
    
    // Performance metrics
    pub query_latency_sum: AtomicU64, // in microseconds
    pub query_latency_count: AtomicU64,
    
    // Error metrics
    pub upstream_errors: AtomicU64,
    pub timeout_errors: AtomicU64,
    pub parse_errors: AtomicU64,
    
    // Upstream health metrics
    pub upstream_metrics: DashMap<String, UpstreamMetrics>,
    
    // Per-plugin metrics
    pub plugin_metrics: DashMap<String, PluginMetrics>,
}

/// 上游服务器指标
#[derive(Debug, Clone, Default)]
pub struct UpstreamMetrics {
    pub queries: u64,
    pub successes: u64,
    pub failures: u64,
    pub total_latency_us: u64,
}

impl UpstreamMetrics {
    pub fn avg_latency_ms(&self) -> f64 {
        if self.queries == 0 { 0.0 } else { self.total_latency_us as f64 / self.queries as f64 / 1000.0 }
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.queries == 0 { 1.0 } else { self.successes as f64 / self.queries as f64 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PluginMetrics {
    pub executions: u64,
    pub errors: u64,
    pub total_duration_us: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            total_responses: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_stale_hits: AtomicU64::new(0),
            cache_refreshes: AtomicU64::new(0),
            query_latency_sum: AtomicU64::new(0),
            query_latency_count: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            timeout_errors: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            upstream_metrics: DashMap::new(),
            plugin_metrics: DashMap::new(),
        }
    }

    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_response(&self) {
        self.total_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, duration_us: u64) {
        self.query_latency_sum.fetch_add(duration_us, Ordering::Relaxed);
        self.query_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeout_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_stale_hit(&self) {
        self.cache_stale_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_refresh(&self) {
        self.cache_refreshes.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_upstream_query(&self, upstream_name: &str, latency_us: u64, success: bool) {
        let mut entry = self.upstream_metrics.entry(upstream_name.to_string()).or_default();
        entry.queries += 1;
        entry.total_latency_us += latency_us;
        if success {
            entry.successes += 1;
        } else {
            entry.failures += 1;
        }
    }

    pub async fn record_plugin_execution(&self, plugin_name: &str, duration_us: u64, is_error: bool) {
        let mut entry = self.plugin_metrics.entry(plugin_name.to_string()).or_default();
        entry.executions += 1;
        entry.total_duration_us += duration_us;
        if is_error {
            entry.errors += 1;
        }
    }
    /// Generate Prometheus format metrics
    pub async fn to_prometheus_format(&self) -> String {
        let mut output = String::new();

        // Help and type definitions
        output.push_str("# HELP titandns_queries_total Total number of DNS queries received\n");
        output.push_str("# TYPE titandns_queries_total counter\n");
        output.push_str(&format!("titandns_queries_total {}\n\n", 
            self.total_queries.load(Ordering::Relaxed)));

        output.push_str("# HELP titandns_responses_total Total number of DNS responses sent\n");
        output.push_str("# TYPE titandns_responses_total counter\n");
        output.push_str(&format!("titandns_responses_total {}\n\n", 
            self.total_responses.load(Ordering::Relaxed)));

        output.push_str("# HELP titandns_cache_hits_total Cache hit count\n");
        output.push_str("# TYPE titandns_cache_hits_total counter\n");
        output.push_str(&format!("titandns_cache_hits_total {}\n\n", 
            self.cache_hits.load(Ordering::Relaxed)));

        output.push_str("# HELP titandns_cache_misses_total Cache miss count\n");
        output.push_str("# TYPE titandns_cache_misses_total counter\n");
        output.push_str(&format!("titandns_cache_misses_total {}\n\n", 
            self.cache_misses.load(Ordering::Relaxed)));

        // Cache hit ratio
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total_cache_queries = hits + misses;
        let hit_ratio = if total_cache_queries > 0 {
            hits as f64 / total_cache_queries as f64
        } else {
            0.0
        };
        output.push_str("# HELP titandns_cache_hit_ratio Cache hit ratio (0-1)\n");
        output.push_str("# TYPE titandns_cache_hit_ratio gauge\n");
        output.push_str(&format!("titandns_cache_hit_ratio {:.4}\n\n", hit_ratio));

        // Average latency
        let latency_sum = self.query_latency_sum.load(Ordering::Relaxed);
        let latency_count = self.query_latency_count.load(Ordering::Relaxed);
        let avg_latency_us = if latency_count > 0 {
            latency_sum / latency_count
        } else {
            0
        };
        output.push_str("# HELP titandns_query_latency_microseconds_avg Average query latency\n");
        output.push_str("# TYPE titandns_query_latency_microseconds_avg gauge\n");
        output.push_str(&format!("titandns_query_latency_microseconds_avg {}\n\n", avg_latency_us));

        // Errors
        output.push_str("# HELP titandns_upstream_errors_total Upstream query errors\n");
        output.push_str("# TYPE titandns_upstream_errors_total counter\n");
        output.push_str(&format!("titandns_upstream_errors_total {}\n\n", 
            self.upstream_errors.load(Ordering::Relaxed)));

        output.push_str("# HELP titandns_timeout_errors_total Timeout errors\n");
        output.push_str("# TYPE titandns_timeout_errors_total counter\n");
        output.push_str(&format!("titandns_timeout_errors_total {}\n\n", 
            self.timeout_errors.load(Ordering::Relaxed)));

        output.push_str("# HELP titandns_parse_errors_total Parse errors\n");
        output.push_str("# TYPE titandns_parse_errors_total counter\n");
        output.push_str(&format!("titandns_parse_errors_total {}\n\n", 
            self.parse_errors.load(Ordering::Relaxed)));

        // Plugin metrics
        if !self.plugin_metrics.is_empty() {
            output.push_str("# HELP titandns_plugin_executions_total Plugin execution count\n");
            output.push_str("# TYPE titandns_plugin_executions_total counter\n");
            for entry in self.plugin_metrics.iter() {
                let plugin_name = entry.key();
                let metrics = entry.value();
                output.push_str(&format!(
                    "titandns_plugin_executions_total{plugin=\"{}\"} {}\n",
                    plugin_name, metrics.executions
                ));
            }
            output.push('\n');

            output.push_str("# HELP titandns_plugin_errors_total Plugin error count\n");
            output.push_str("# TYPE titandns_plugin_errors_total counter\n");
            for entry in self.plugin_metrics.iter() {
                let plugin_name = entry.key();
                let metrics = entry.value();
                output.push_str(&format!(
                    "titandns_plugin_errors_total{plugin=\"{}\"} {}\n",
                    plugin_name, metrics.errors
                ));
            }
            output.push('\n');

            output.push_str("# HELP titandns_plugin_duration_microseconds_total Total plugin execution time\n");
            output.push_str("# TYPE titandns_plugin_duration_microseconds_total counter\n");
            for entry in self.plugin_metrics.iter() {
                let plugin_name = entry.key();
                let metrics = entry.value();
                output.push_str(&format!(
                    "titandns_plugin_duration_microseconds_total{plugin=\"{}\"} {}\n",
                    plugin_name, metrics.total_duration_us
                ));
            }
            output.push('\n');
        }

        output
    }
impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Create metrics endpoint router
pub fn create_metrics_router(metrics: Arc<MetricsCollector>) -> Router {
    Router::new()
        .route("/metrics", get(move || metrics_handler(metrics.clone())))
}

async fn metrics_handler(metrics: Arc<MetricsCollector>) -> impl IntoResponse {
    let prometheus_output = metrics.to_prometheus_format().await;
    (StatusCode::OK, prometheus_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_basic() {
        let metrics = MetricsCollector::new();
        metrics.record_query();
        metrics.record_response();
        assert_eq!(metrics.total_queries.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_responses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_metrics() {
        let metrics = MetricsCollector::new();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.cache_misses.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_prometheus_format() {
        let metrics = MetricsCollector::new();
        metrics.record_query();
        metrics.record_cache_hit();
        
        let output = metrics.to_prometheus_format().await;
        assert!(output.contains("titandns_queries_total 1"));
        assert!(output.contains("titandns_cache_hits_total 1"));
    }
}
