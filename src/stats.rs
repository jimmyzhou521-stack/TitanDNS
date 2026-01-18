use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::RwLock;
use std::collections::VecDeque;
use chrono::Utc;

/// Global DNS Statistics Collector
#[derive(Debug)]
pub struct DnsStats {
    // Counters
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub blocked_count: AtomicU64,
    
    // XDP Stats
    pub xdp_hits: AtomicU64,

    // Latency tracking (wrapped in Arc for cloning)
    latency_samples: Arc<RwLock<VecDeque<u64>>>,
    
    // Top domains/clients (domain/ip -> count)
    pub domain_counts: DashMap<String, u64>,
    pub client_counts: DashMap<String, u64>,
    
    // Detailed Protocol Stats
    pub rcode_counts: DashMap<String, u64>,
    pub qtype_counts: DashMap<String, u64>,
    pub strategy_counts: DashMap<String, u64>, // e.g. "domestic", "foreign", "blocked"

    // Recent blocked domains (wrapped in Arc for cloning)
    recent_blocked: Arc<RwLock<VecDeque<BlockedEntry>>>,
    
    // Configuration
    pub blocked_limit: AtomicUsize, // Default 100

    // Uptime tracking
    pub start_time: tokio::time::Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedEntry {
    pub domain: String,
    pub timestamp: String,  // ISO 8601 format string
}

#[derive(Serialize)]
pub struct StatsSnapshot {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub xdp_hits: u64,     // NEW
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub blocked_count: u64,
    pub avg_latency_ms: f64,
    pub top_domains: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
    pub rcode_breakdown: std::collections::HashMap<String, u64>,
    pub qtype_breakdown: std::collections::HashMap<String, u64>,
    pub strategy_breakdown: std::collections::HashMap<String, u64>,
    pub recent_blocked: Vec<BlockedEntry>,
    pub cache_entries: u64,
    pub cache_memory_bytes: u64,
    pub uptime_seconds: u64,
}

impl DnsStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            xdp_hits: AtomicU64::new(0), // NEW
            cache_misses: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            latency_samples: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            domain_counts: DashMap::new(),
            client_counts: DashMap::new(),
            rcode_counts: DashMap::new(),
            qtype_counts: DashMap::new(),
            strategy_counts: DashMap::new(),
            recent_blocked: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            blocked_limit: AtomicUsize::new(100), // Default
            start_time: tokio::time::Instant::now(),
        })
    }

    /// Set limit for recent blocked logs
    pub fn set_blocked_limit(&self, limit: usize) {
        self.blocked_limit.store(limit, Ordering::Relaxed);
    }
    
    pub fn set_xdp_hits(&self, count: u64) {
        self.xdp_hits.store(count, Ordering::Relaxed);
    }

    /// Record a DNS query
    pub fn record_query(&self, domain: &str, client_ip: &str, latency_us: u64) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        
        // Update domain count
        self.domain_counts
            .entry(domain.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        // Update client count
        self.client_counts
            .entry(client_ip.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        // Record latency sample (async-safe)
        if let Ok(mut guard) = self.latency_samples.try_write() {
            if guard.len() >= 1000 {
                guard.pop_front();
            }
            guard.push_back(latency_us);
        }

        // Memory Protection: Prevent DashMap from indefinite growth
        // If we track too many distinct domains/clients (e.g. DDOS or random subdomains), clear stats.
        if self.domain_counts.len() > 50000 {
            self.domain_counts.clear();
        }
        if self.client_counts.len() > 10000 {
            self.client_counts.clear();
        }
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a blocked domain
    pub fn record_blocked(&self, domain: &str) {
        self.blocked_count.fetch_add(1, Ordering::Relaxed);
        
        let entry = BlockedEntry {
            domain: domain.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        
        let limit = self.blocked_limit.load(Ordering::Relaxed);
        if let Ok(mut guard) = self.recent_blocked.try_write() {
            if guard.len() >= limit {
                guard.pop_front();
            }
            guard.push_back(entry);
        }

        // Also record as a "Blocked" strategy
        self.record_strategy("Blocked");
    }

    /// Record routing strategy (e.g. "SmartDNS", "Proxy", "Blocked")
    pub fn record_strategy(&self, strategy: &str) {
        self.strategy_counts
            .entry(strategy.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Record detailed stats
    pub fn record_details(&self, qtype: &str, rcode: &str) {
        self.qtype_counts.entry(qtype.to_string()).and_modify(|c| *c += 1).or_insert(1);
        self.rcode_counts.entry(rcode.to_string()).and_modify(|c| *c += 1).or_insert(1);
    }

    /// Get a snapshot of current statistics
    pub async fn snapshot(&self) -> StatsSnapshot {
        let total = self.total_queries.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let xdp = self.xdp_hits.load(Ordering::Relaxed); // NEW
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let blocked = self.blocked_count.load(Ordering::Relaxed);
        
        // Calculate cache hit rate (Include XDP in Hits?)
        // Let's say Total Hit = Mem Hit + XDP Hit
        let total_hits = hits + xdp;
        let total_cache = total_hits + misses; // Total handled requests approx (missed ones also counted in total)
        
        let hit_rate = if total_cache > 0 {
            (total_hits as f64 / total_cache as f64) * 100.0
        } else {
            0.0
        };
        
        // Calculate average latency
        let avg_latency = {
            let samples = self.latency_samples.read().await;
            if samples.is_empty() {
                0.0
            } else {
                let sum: u64 = samples.iter().sum();
                (sum as f64 / samples.len() as f64) / 1000.0  // Convert to ms
            }
        };
        
        // Get top 10 domains
        let mut domains: Vec<_> = self.domain_counts.iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        domains.sort_by(|a, b| b.1.cmp(&a.1));
        domains.truncate(10);
        
        // Get top 10 clients
        let mut clients: Vec<_> = self.client_counts.iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        clients.sort_by(|a, b| b.1.cmp(&a.1));
        clients.truncate(10);
        
        // Get recent blocked
        let blocked_list = {
            let list = self.recent_blocked.read().await;
            list.iter().rev().take(10).cloned().collect()
        };
        
        // Helper to convert DashMap to HashMap for snapshot
        let to_map = |dm: &DashMap<String, u64>| -> std::collections::HashMap<String, u64> {
            dm.iter().map(|r| (r.key().clone(), *r.value())).collect()
        };

        StatsSnapshot {
            total_queries: total + xdp, // XDP queries didn't go through record_query
            cache_hits: hits,
            xdp_hits: xdp,
            cache_misses: misses,
            cache_hit_rate: (hit_rate * 10.0).round() / 10.0,
            blocked_count: blocked,
            avg_latency_ms: (avg_latency * 10.0).round() / 10.0,
            top_domains: domains,
            top_clients: clients,
            rcode_breakdown: to_map(&self.rcode_counts),
            qtype_breakdown: to_map(&self.qtype_counts),
            strategy_breakdown: to_map(&self.strategy_counts),
            recent_blocked: blocked_list,
            cache_entries: 0,
            cache_memory_bytes: 0,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
}

impl Default for DnsStats {
    fn default() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            xdp_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            latency_samples: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            domain_counts: DashMap::new(),
            client_counts: DashMap::new(),
            rcode_counts: DashMap::new(),
            qtype_counts: DashMap::new(),
            strategy_counts: DashMap::new(),
            recent_blocked: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            blocked_limit: AtomicUsize::new(100),
            start_time: tokio::time::Instant::now(),
        }
    }
}

// Global STATS instance - accessible from anywhere
lazy_static::lazy_static! {
    pub static ref STATS: Arc<DnsStats> = DnsStats::new();
}
