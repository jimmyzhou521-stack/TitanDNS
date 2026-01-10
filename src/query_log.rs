use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use serde::Serialize;
use chrono::Local;
use lazy_static::lazy_static;

/// Single Query Log Entry
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    pub timestamp: String, // ISO 8601 or readable string
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub strategy: String, // e.g. "Cache", "Forward", "FakeIP", "Block"
    pub upstream: Option<String>,
    pub latency_ms: u64,
    pub rcode: String,
}

// Global Configuration
static MAX_LOG_SIZE: AtomicUsize = AtomicUsize::new(5000);
static LOG_ENABLED: AtomicUsize = AtomicUsize::new(1); // 1 = true, 0 = false

lazy_static! {
    /// In-memory Ring Buffer for Query Logs
    static ref QUERY_LOG_BUFFER: RwLock<VecDeque<QueryLogEntry>> = RwLock::new(VecDeque::with_capacity(5000));
}

/// Initialize Query Log Configuration
pub fn init_query_log(enabled: bool, max_size: usize) {
    LOG_ENABLED.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    MAX_LOG_SIZE.store(max_size, Ordering::Relaxed);
}

/// Append a new log entry
pub async fn log_request(
    client_ip: String,
    domain: String,
    qtype: String,
    strategy: String,
    upstream: Option<String>,
    latency_ms: u64,
    rcode: String,
) {
    // Fast path check
    if LOG_ENABLED.load(Ordering::Relaxed) == 0 {
        return;
    }

    let entry = QueryLogEntry {
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        client_ip,
        domain,
        qtype,
        strategy,
        upstream,
        latency_ms,
        rcode,
    };

    let max_size = MAX_LOG_SIZE.load(Ordering::Relaxed);
    let mut buffer = QUERY_LOG_BUFFER.write().await;

    if buffer.len() >= max_size {
        buffer.pop_front(); // Remove oldest
    }
    buffer.push_back(entry);
}

/// Get recent logs (reversed: newest first)
pub async fn get_recent_logs(limit: usize) -> Vec<QueryLogEntry> {
    if LOG_ENABLED.load(Ordering::Relaxed) == 0 {
        return Vec::new();
    }

    let buffer = QUERY_LOG_BUFFER.read().await;
    // Iterate from back (newest) to front, take limit
    buffer.iter().rev().take(limit).cloned().collect()
}
