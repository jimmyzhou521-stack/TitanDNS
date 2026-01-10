// TitanDNS AutoPilot Module - AIOps Smart Routing Engine
// Provides intelligent upstream selection based on real-time health metrics
//
// Features:
// - Real-time latency monitoring with exponential moving average
// - Jitter calculation for stability scoring
// - Automatic circuit breaker (unhealthy detection)
// - Score-based dynamic routing (no more blind race)
// - Predictive failover before actual failure

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::PathBuf;
use parking_lot::RwLock;

use tracing::{debug, info, warn};
use dashmap::DashMap;
use chrono::Timelike;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Maximum history samples to keep for each upstream
const HISTORY_SIZE: usize = 100;
/// Maximum time-based history (15 minutes in seconds)
const HISTORY_DURATION_SECS: u64 = 15 * 60;

// [优化] 调整权重 - 更重视成功率和稳定性
/// Default weight for latency in score calculation (0.0 - 1.0)
const DEFAULT_LATENCY_WEIGHT: f64 = 0.35;      // 50% → 35% 降低延迟权重
/// Default weight for jitter in score calculation
const DEFAULT_JITTER_WEIGHT: f64 = 0.15;       // 20% → 15%
/// Default weight for success rate in score calculation
const DEFAULT_SUCCESS_WEIGHT: f64 = 0.40;      // 30% → 40% 提高成功率权重
/// Default weight for packet loss rate in score calculation
const DEFAULT_PACKET_LOSS_WEIGHT: f64 = 0.10;  // 新增：包丢率惩罚

// ==================== Dynamic Weight Manager ====================

/// Dynamic weight configuration for AutoPilot scoring
#[derive(Debug, Clone)]
pub struct WeightConfig {
    pub latency_weight: f64,
    pub jitter_weight: f64,
    pub success_weight: f64,
    pub pktloss_weight: f64,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            latency_weight: DEFAULT_LATENCY_WEIGHT,
            jitter_weight: DEFAULT_JITTER_WEIGHT,
            success_weight: DEFAULT_SUCCESS_WEIGHT,
            pktloss_weight: DEFAULT_PACKET_LOSS_WEIGHT,
        }
    }
}

impl WeightConfig {
    /// Validate weight configuration (sum should be close to 1.0)
    pub fn is_valid(&self) -> bool {
        let sum = self.latency_weight + self.jitter_weight + self.success_weight + self.pktloss_weight;
        (sum - 1.0).abs() < 0.01
    }

    /// Get description of current configuration
    pub fn description(&self) -> String {
        format!(
            "延迟:{:.0}% 抖动:{:.0}% 成功率:{:.0}% 丢包:{:.0}%",
            self.latency_weight * 100.0,
            self.jitter_weight * 100.0,
            self.success_weight * 100.0,
            self.pktloss_weight * 100.0
        )
    }
}

/// Global dynamic weight manager (singleton pattern)
struct WeightManager {
    config: RwLock<WeightConfig>,
}

static WEIGHT_MANAGER: Lazy<WeightManager> = Lazy::new(|| {
    info!("🎯 AutoPilot 动态权重管理器初始化");
    WeightManager {
        config: RwLock::new(WeightConfig::default()),
    }
});

static WEIGHT_MANAGER_DOMESTIC: Lazy<WeightManager> = Lazy::new(|| {
    WeightManager {
        config: RwLock::new(WeightConfig::default()),
    }
});

static WEIGHT_MANAGER_FOREIGN: Lazy<WeightManager> = Lazy::new(|| {
    WeightManager {
        config: RwLock::new(WeightConfig::default()),
    }
});

fn weight_manager_for_scope(scope: NetworkScope) -> &'static WeightManager {
    match scope {
        NetworkScope::Domestic => &WEIGHT_MANAGER_DOMESTIC,
        NetworkScope::Foreign => &WEIGHT_MANAGER_FOREIGN,
        _ => &WEIGHT_MANAGER,
    }
}

/// Get current weight configuration
pub fn get_current_weights() -> WeightConfig {
    get_current_weights_for_scope(NetworkScope::Global)
}

/// Get current weight configuration for a scope
pub fn get_current_weights_for_scope(scope: NetworkScope) -> WeightConfig {
    weight_manager_for_scope(scope).config.read().clone()
}

/// Set custom weight configuration (use with caution)
pub fn set_weights(config: WeightConfig) -> Result<(), String> {
    set_weights_for_scope(NetworkScope::Global, config)
}

/// Set custom weight configuration for a scope
pub fn set_weights_for_scope(scope: NetworkScope, config: WeightConfig) -> Result<(), String> {
    if !config.is_valid() {
        return Err("权重总和必须接近 1.0".to_string());
    }
    info!("🔄 AutoPilot 权重更新({:?}): {}", scope, config.description());
    *weight_manager_for_scope(scope).config.write() = config;
    Ok(())
}

/// Consecutive failures before marking unhealthy
const FAILURE_THRESHOLD: u32 = 3;
/// Cooldown period before retrying unhealthy upstream
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(30);
/// Probe interval for active health checks
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// AutoPilot persistence
const AUTOPILOT_PERSIST_INTERVAL: Duration = Duration::from_secs(300); // 5 min
const AUTOPILOT_PERSIST_DEFAULT_PATH: &str = "/var/lib/titandns/autopilot_state.json";

// Prefetch throttling
const PREFETCH_QPS_LIMIT: u64 = 300;          // current QPS guard
const PREFETCH_AVG_QPS_30S_LIMIT: f64 = 200.0; // avg QPS guard
const PREFETCH_COOLDOWN: Duration = Duration::from_secs(120);
const AUTOPILOT_WEIGHT_TUNE_INTERVAL: Duration = Duration::from_secs(300); // 5 min

/// A single probe result with timestamp
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub timestamp: Instant,
    pub latency_ms: Option<u64>,  // None = failed
    pub probe_type: ProbeType,
}

/// Type of health probe
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProbeType {
    /// Real DNS query observation
    DnsQuery,
    /// Active ICMP ping
    IcmpPing,
    /// Active DNS ping (query for ".")
    DnsPing,
    /// TCP connect test
    TcpConnect,
}

/// Detailed health metrics for a single upstream
#[derive(Debug)]
pub struct UpstreamMetrics {
    /// Unique identifier (e.g., "udp://119.29.29.29:53")
    pub label: String,
    
    /// Is this upstream currently considered healthy?
    healthy: AtomicBool,
    
    /// Ring buffer of recent RTT samples (in milliseconds) - for quick access
    rtt_history: RwLock<VecDeque<u64>>,
    
    /// Time-based probe history (keeps 15 minutes of data)
    probe_history: RwLock<VecDeque<ProbeResult>>,
    
    /// Exponential moving average of RTT
    avg_rtt_ms: AtomicU64,
    
    /// Minimum RTT observed
    min_rtt_ms: AtomicU64,
    
    /// Maximum RTT observed  
    max_rtt_ms: AtomicU64,
    
    /// Jitter (variance) in milliseconds
    jitter_ms: AtomicU64,
    
    /// Total successful queries
    success_count: AtomicU64,
    
    /// Total failed queries
    failure_count: AtomicU64,
    
    /// Consecutive failures (resets on success)
    consecutive_failures: AtomicU64,
    
    /// Last time this upstream was probed
    last_probe: RwLock<Instant>,
    
    /// Last time this upstream was marked unhealthy
    last_unhealthy: RwLock<Option<Instant>>,
    
    /// Calculated score (higher is better) - updated periodically
    score: AtomicU64,
}

impl UpstreamMetrics {
    pub fn new(label: String) -> Self {
        Self {
            label,
            healthy: AtomicBool::new(true),
            rtt_history: RwLock::new(VecDeque::with_capacity(HISTORY_SIZE)),
            probe_history: RwLock::new(VecDeque::with_capacity(1000)), // ~15 min at 1 probe/sec
            avg_rtt_ms: AtomicU64::new(50), // Start with 50ms assumption
            min_rtt_ms: AtomicU64::new(u64::MAX),
            max_rtt_ms: AtomicU64::new(0),
            jitter_ms: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            last_probe: RwLock::new(Instant::now()),
            last_unhealthy: RwLock::new(None),
            score: AtomicU64::new(1000), // Start with max score
        }
    }
    
    /// Record a successful query with its latency
    pub fn record_success(&self, latency_ms: u64) {
        self.record_probe(Some(latency_ms), ProbeType::DnsQuery);
    }
    
    /// Record a failed query
    pub fn record_failure(&self) {
        self.record_probe(None, ProbeType::DnsQuery);
    }
    
    /// Record a probe result (unified method for all probe types)
    pub fn record_probe(&self, latency_ms: Option<u64>, probe_type: ProbeType) {
        let now = Instant::now();
        
        // Add to time-based probe history
        {
            let mut history = self.probe_history.write();
            
            // Evict old entries (> 15 minutes)
            while let Some(front) = history.front() {
                if front.timestamp.elapsed().as_secs() > HISTORY_DURATION_SECS {
                    history.pop_front();
                } else {
                    break;
                }
            }
            
            history.push_back(ProbeResult {
                timestamp: now,
                latency_ms,
                probe_type,
            });
        }
        
        if let Some(latency) = latency_ms {
            // ===== SUCCESS =====
            self.success_count.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);
            
            // Mark healthy if was unhealthy
            if !self.healthy.load(Ordering::Relaxed) {
                info!("✅ Upstream '{}' recovered (latency: {}ms)", self.label, latency);
                self.healthy.store(true, Ordering::Relaxed);
            }
            
            // Update RTT history (for quick avg calculation)
            {
                let mut history = self.rtt_history.write();
                if history.len() >= HISTORY_SIZE {
                    history.pop_front();
                }
                history.push_back(latency);
            }
            
            // Update min/max RTT
            let old_min = self.min_rtt_ms.load(Ordering::Relaxed);
            if latency < old_min {
                self.min_rtt_ms.store(latency, Ordering::Relaxed);
            }
            let old_max = self.max_rtt_ms.load(Ordering::Relaxed);
            if latency > old_max {
                self.max_rtt_ms.store(latency, Ordering::Relaxed);
            }
            
            // Update EMA (Exponential Moving Average)
            let old_avg = self.avg_rtt_ms.load(Ordering::Relaxed);
            let new_avg = (old_avg * 7 + latency * 3) / 10;
            self.avg_rtt_ms.store(new_avg, Ordering::Relaxed);
            
            // Calculate jitter
            let jitter = if latency > new_avg { latency - new_avg } else { new_avg - latency };
            let old_jitter = self.jitter_ms.load(Ordering::Relaxed);
            let new_jitter = (old_jitter * 7 + jitter * 3) / 10;
            self.jitter_ms.store(new_jitter, Ordering::Relaxed);
        } else {
            // ===== FAILURE =====
            self.failure_count.fetch_add(1, Ordering::Relaxed);
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            
            if failures >= FAILURE_THRESHOLD as u64 {
                if self.healthy.swap(false, Ordering::Relaxed) {
                    warn!("⚠️ Upstream '{}' marked UNHEALTHY (consecutive failures: {})", 
                          self.label, failures);
                    *self.last_unhealthy.write() = Some(now);
                }
            }
        }
        
        // Update probe time
        *self.last_probe.write() = now;
        
        // Recalculate score
        self.update_score();
    }
    
    /// Get packet loss rate (0.0 - 1.0) for last 15 minutes
    pub fn get_packet_loss_rate(&self) -> f64 {
        let history = self.probe_history.read();
        if history.is_empty() {
            return 0.0;
        }
        
        let total = history.len();
        let failed = history.iter().filter(|p| p.latency_ms.is_none()).count();
        failed as f64 / total as f64
    }
    
    /// Get P95 latency (95th percentile) from recent history
    pub fn get_p95_latency(&self) -> u64 {
        let history = self.rtt_history.read();
        if history.is_empty() {
            return self.avg_rtt_ms.load(Ordering::Relaxed);
        }
        
        let mut sorted: Vec<u64> = history.iter().copied().collect();
        sorted.sort_unstable();
        
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let idx = p95_idx.min(sorted.len() - 1);
        sorted[idx]
    }
    
    /// Get min RTT
    pub fn get_min_rtt(&self) -> u64 {
        let v = self.min_rtt_ms.load(Ordering::Relaxed);
        if v == u64::MAX { 0 } else { v }
    }
    
    /// Get max RTT
    pub fn get_max_rtt(&self) -> u64 {
        self.max_rtt_ms.load(Ordering::Relaxed)
    }
    
    /// Get probe count in last N seconds
    pub fn get_probe_count(&self, seconds: u64) -> usize {
        let history = self.probe_history.read();
        history.iter()
            .filter(|p| p.timestamp.elapsed().as_secs() <= seconds)
            .count()
    }
    
    /// Get jitter in milliseconds
    pub fn get_jitter_ms(&self) -> u64 {
        self.jitter_ms.load(Ordering::Relaxed)
    }
    
    /// Check if this upstream is available for queries
    pub fn is_available(&self) -> bool {
        if self.healthy.load(Ordering::Relaxed) {
            return true;
        }
        
        // Check if cooldown expired - allow retry
        if let Some(unhealthy_time) = *self.last_unhealthy.read() {
            if unhealthy_time.elapsed() > RECOVERY_COOLDOWN {
                debug!("🔄 Upstream '{}' cooldown expired, allowing retry", self.label);
                return true;
            }
        }
        
        false
    }
    
    /// Get the current score (higher is better, range 0-1000)
    pub fn get_score(&self) -> u64 {
        self.score.load(Ordering::Relaxed)
    }
    
    /// Get average RTT in milliseconds
    pub fn get_avg_rtt(&self) -> u64 {
        self.avg_rtt_ms.load(Ordering::Relaxed)
    }
    
    /// Get success rate (0.0 - 1.0)
    pub fn get_success_rate(&self) -> f64 {
        let success = self.success_count.load(Ordering::Relaxed);
        let failure = self.failure_count.load(Ordering::Relaxed);
        let total = success + failure;
        
        if total == 0 {
            return 1.0; // Assume healthy if no data
        }
        
        success as f64 / total as f64
    }
    
    /// Recalculate the composite score
    fn update_score(&self) {
        let rtt = self.avg_rtt_ms.load(Ordering::Relaxed);
        let jitter = self.jitter_ms.load(Ordering::Relaxed);
        let success_rate = self.get_success_rate();
        let packet_loss = self.get_packet_loss_rate();

        // [优化] 使用对数曲线计算 RTT 分数 (更平滑，避免极端差异)
        // 5ms 以下: 1000分 (满分)
        // 10ms: ~861分 (原100分)
        // 30ms: ~642分 (原33分)
        // 100ms: ~400分 (原10分)
        // 200ms: ~50分 (几乎不用)
        let rtt_score = if rtt <= 5 {
            1000.0
        } else if rtt >= 200 {
            50.0
        } else {
            // 对数递减曲线: 1000 - ln(rtt/5) * 200
            let ratio = rtt as f64 / 5.0;
            let decay = ratio.ln() * 200.0;
            (1000.0 - decay).max(50.0).min(1000.0)
        };

        // Normalize jitter: 0ms = 1000, 100ms = 0
        let jitter_score = ((100.0 - (jitter as f64).min(100.0)) * 10.0).max(0.0);

        // Success rate: 1.0 = 1000, 0.0 = 0
        let success_score = success_rate * 1000.0;

        // [优化] 包丢率评分: 0% loss = 1000, 10% loss = 0
        let pktloss_score = ((1.0 - packet_loss.min(0.1)) * 10000.0).max(0.0).min(1000.0);

        // [动态权重] 使用动态权重配置
        let weights = get_current_weights_for_scope(scope_for_label(&self.label));

        // Weighted composite score
        let composite = rtt_score * weights.latency_weight
                      + jitter_score * weights.jitter_weight
                      + success_score * weights.success_weight
                      + pktloss_score * weights.pktloss_weight;

        // Apply health penalty
        let final_score = if self.healthy.load(Ordering::Relaxed) {
            composite
        } else {
            composite * 0.1 // 90% penalty for unhealthy
        };

        self.score.store(final_score as u64, Ordering::Relaxed);
    }
    
    /// Get an enhanced summary with all sensor data
    pub fn summary(&self) -> String {
        format!(
            "{}: score={} rtt={}ms(min={}/max={}/p95={}) jitter={}ms pktloss={:.1}% success={:.1}% {}",
            self.label,
            self.get_score(),
            self.get_avg_rtt(),
            self.get_min_rtt(),
            self.get_max_rtt(),
            self.get_p95_latency(),
            self.jitter_ms.load(Ordering::Relaxed),
            self.get_packet_loss_rate() * 100.0,
            self.get_success_rate() * 100.0,
            if self.is_available() { "✅" } else { "❌" }
        )
    }
}

// ============== Hot Domains Tracker ==============

/// Maximum number of hot domains to track
const MAX_HOT_DOMAINS: usize = 100;

/// Domain access statistics
#[derive(Debug, Clone)]
pub struct DomainStats {
    /// Domain name
    pub domain: String,
    /// Total access count
    pub access_count: u64,
    /// Access count by hour of day (0-23)
    pub hourly_counts: [u64; 24],
    /// Last access timestamp
    pub last_access: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainStatsSnapshot {
    pub access_count: u64,
    pub hourly_counts: [u64; 24],
    pub age_secs: u64,
}

impl DomainStats {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            access_count: 0,
            hourly_counts: [0; 24],
            last_access: Instant::now(),
        }
    }
    
    /// Record an access
    pub fn record_access(&mut self, hour: usize) {
        self.access_count += 1;
        if hour < 24 {
            self.hourly_counts[hour] += 1;
        }
        self.last_access = Instant::now();
    }
    
    /// Convert to persistence snapshot
    fn to_snapshot(&self) -> DomainStatsSnapshot {
        DomainStatsSnapshot {
            access_count: self.access_count,
            hourly_counts: self.hourly_counts,
            age_secs: self.last_access.elapsed().as_secs(),
        }
    }

    /// Restore from persistence snapshot
    fn from_snapshot(domain: String, snapshot: DomainStatsSnapshot) -> Self {
        Self {
            domain,
            access_count: snapshot.access_count,
            hourly_counts: snapshot.hourly_counts,
            last_access: Instant::now() - Duration::from_secs(snapshot.age_secs),
        }
    }

    /// Get predicted access probability for a given hour
    pub fn predict_access_probability(&self, hour: usize) -> f64 {
        if self.access_count == 0 || hour >= 24 {
            return 0.0;
        }
        self.hourly_counts[hour] as f64 / self.access_count as f64
    }
}

/// Hot domains tracker with predictive capabilities
pub struct HotDomains {
    /// Domain -> Stats mapping
    domains: RwLock<std::collections::HashMap<String, DomainStats>>,
    /// Prefetch callback (domain to prefetch)
    prefetch_callback: RwLock<Option<Box<dyn Fn(String) + Send + Sync>>>,
    /// Last prefetch time (cooldown)
    last_prefetch: RwLock<Instant>,
}

impl HotDomains {
    pub fn new() -> Self {
        Self {
            domains: RwLock::new(std::collections::HashMap::new()),
            prefetch_callback: RwLock::new(None),
            last_prefetch: RwLock::new(Instant::now() - PREFETCH_COOLDOWN),
        }
    }
    
    /// Record a domain access
    pub fn record_access(&self, domain: &str) {
        // Get current hour
        let hour = {
            use std::time::SystemTime;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ((now / 3600) % 24) as usize
        };
        
        let mut domains = self.domains.write();
        
        // Normalize domain (remove trailing dot)
        let domain = domain.trim_end_matches('.');
        
        if let Some(stats) = domains.get_mut(domain) {
            stats.record_access(hour);
        } else {
            // Check if we need to evict
            if domains.len() >= MAX_HOT_DOMAINS {
                // Evict least accessed domain
                if let Some(min_domain) = domains.iter()
                    .min_by_key(|(_, s)| s.access_count)
                    .map(|(k, _)| k.clone())
                {
                    domains.remove(&min_domain);
                }
            }
            
            let mut stats = DomainStats::new(domain.to_string());
            stats.record_access(hour);
            domains.insert(domain.to_string(), stats);
        }
    }
    
    /// Get top N hot domains
    pub fn get_top_n(&self, n: usize) -> Vec<(String, u64)> {
        let domains = self.domains.read();
        let mut sorted: Vec<_> = domains.iter()
            .map(|(k, v)| (k.clone(), v.access_count))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(n).collect()
    }
    
    /// Get domains that should be prefetched for the next hour
    pub fn get_prefetch_candidates(&self, threshold: f64) -> Vec<String> {
        let next_hour = {
            use std::time::SystemTime;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            (((now / 3600) + 1) % 24) as usize
        };
        
        let domains = self.domains.read();
        domains.iter()
            .filter(|(_, stats)| stats.predict_access_probability(next_hour) >= threshold)
            .map(|(domain, _)| domain.clone())
            .collect()
    }
    
    /// Set prefetch callback
    pub fn set_prefetch_callback<F>(&self, callback: F)
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        *self.prefetch_callback.write() = Some(Box::new(callback));
    }
    
    /// Trigger prefetch for high-probability domains
    pub fn trigger_prefetch(&self, threshold: f64) {
        let now = Instant::now();
        let last = *self.last_prefetch.read();
        if now.duration_since(last) < PREFETCH_COOLDOWN {
            debug!("?? Prefetch skipped: cooldown active ({}s)", PREFETCH_COOLDOWN.as_secs());
            return;
        }

        let current_qps = get_current_qps();
        let avg_qps = get_avg_qps(30);
        if current_qps > PREFETCH_QPS_LIMIT || avg_qps > PREFETCH_AVG_QPS_30S_LIMIT {
            debug!(
                "?? Prefetch skipped: high QPS (current={}, avg30s={:.1})",
                current_qps,
                avg_qps
            );
            return;
        }

        let candidates = self.get_prefetch_candidates(threshold);
        if candidates.is_empty() {
            return;
        }

        *self.last_prefetch.write() = now;

        if let Some(callback) = &*self.prefetch_callback.read() {
            for domain in candidates {
                debug!("?? Prefetching predicted hot domain: {}", domain);
                callback(domain);
            }
        }
    }
    
    /// Get statistics summary
    pub fn summary(&self) -> String {
        let domains = self.domains.read();
        let total_access: u64 = domains.values().map(|s| s.access_count).sum();
        format!(
            "HotDomains: {} tracked, {} total accesses",
            domains.len(),
            total_access
        )
    }
    
    /// Get number of tracked domains
    pub fn get_domain_count(&self) -> usize {
        self.domains.read().len()
    }
}

/// Global hot domains tracker
pub static HOT_DOMAINS: Lazy<Arc<HotDomains>> = Lazy::new(|| {
    Arc::new(HotDomains::new())
});

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AutopilotSnapshot {
    domain_memory: HashMap<String, DomainMemorySnapshot>,
    client_domain_memory: HashMap<String, DomainMemorySnapshot>,
    hot_domains: HashMap<String, DomainStatsSnapshot>,
}

fn get_autopilot_state_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITANDNS_AUTOPILOT_STATE") {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("disabled") {
            return None;
        }
        return Some(PathBuf::from(trimmed));
    }
    Some(PathBuf::from(AUTOPILOT_PERSIST_DEFAULT_PATH))
}

fn build_autopilot_snapshot() -> AutopilotSnapshot {
    let domain_memory: HashMap<String, DomainMemorySnapshot> = DOMAIN_MEMORY
        .iter()
        .map(|e| (e.key().clone(), e.value().to_snapshot()))
        .collect();
    let client_domain_memory: HashMap<String, DomainMemorySnapshot> = CLIENT_DOMAIN_MEMORY
        .iter()
        .map(|e| (e.key().clone(), e.value().to_snapshot()))
        .collect();
    let hot_domains: HashMap<String, DomainStatsSnapshot> = {
        let domains = HOT_DOMAINS.domains.read();
        domains.iter().map(|(k, v)| (k.clone(), v.to_snapshot())).collect()
    };

    AutopilotSnapshot {
        domain_memory,
        client_domain_memory,
        hot_domains,
    }
}

fn apply_autopilot_snapshot(snapshot: AutopilotSnapshot) {
    DOMAIN_MEMORY.clear();
    for (domain, entry) in snapshot.domain_memory {
        DOMAIN_MEMORY.insert(domain, DomainMemory::from_snapshot(entry));
    }

    CLIENT_DOMAIN_MEMORY.clear();
    for (key, entry) in snapshot.client_domain_memory {
        CLIENT_DOMAIN_MEMORY.insert(key, DomainMemory::from_snapshot(entry));
    }

    let mut domains = HOT_DOMAINS.domains.write();
    domains.clear();
    for (domain, stats) in snapshot.hot_domains {
        domains.insert(domain.clone(), DomainStats::from_snapshot(domain, stats));
    }
}

fn load_autopilot_snapshot(path: &PathBuf) -> Option<AutopilotSnapshot> {
    let content = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&content) {
        Ok(snapshot) => Some(snapshot),
        Err(e) => {
            warn!("?? AutoPilot: Failed to parse snapshot {:?}: {}", path, e);
            None
        }
    }
}

fn save_autopilot_snapshot(path: &PathBuf) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let snapshot = build_autopilot_snapshot();
    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())?;
    Ok(())
}

/// Record a domain access for hot tracking
pub fn track_domain(domain: &str) {
    HOT_DOMAINS.record_access(domain);
}

/// Get top N hot domains
pub fn get_hot_domains(n: usize) -> Vec<(String, u64)> {
    HOT_DOMAINS.get_top_n(n)
}

/// Get prefetch candidates for next hour
pub fn get_prefetch_list(threshold: f64) -> Vec<String> {
    HOT_DOMAINS.get_prefetch_candidates(threshold)
}

// ============== AutoPilot Engine ==============

/// The AutoPilot engine - manages all upstream metrics and provides smart selection
pub struct AutoPilot {
    /// All monitored upstreams
    upstreams: RwLock<Vec<Arc<UpstreamMetrics>>>,
    
    /// Background health check interval
    check_interval: Duration,
    
    /// Probe timeout
    probe_timeout: Duration,
}

impl AutoPilot {
    pub fn new() -> Self {
        Self {
            upstreams: RwLock::new(Vec::new()),
            check_interval: Duration::from_secs(10), // Check every 10 seconds
            probe_timeout: Duration::from_secs(3),
        }
    }
    
    /// Register an upstream for monitoring
    pub fn register(&self, label: String) -> Arc<UpstreamMetrics> {
        let mut upstreams = self.upstreams.write();
        
        // Check if already exists
        if let Some(existing) = upstreams.iter().find(|u| u.label == label) {
            return existing.clone();
        }
        
        // Create new
        let metrics = Arc::new(UpstreamMetrics::new(label.clone()));
        upstreams.push(metrics.clone());
        info!("🛫 AutoPilot: Registered upstream '{}'", label);
        
        metrics
    }
    
    /// Get metrics for an upstream by label
    pub fn get(&self, label: &str) -> Option<Arc<UpstreamMetrics>> {
        self.upstreams.read()
            .iter()
            .find(|u| u.label == label)
            .cloned()
    }
    
    /// Get the best available upstream based on score
    /// Returns labels sorted by score (best first)
    pub fn get_best_upstreams(&self) -> Vec<String> {
        let mut available: Vec<_> = self.upstreams.read()
            .iter()
            .filter(|u| u.is_available())
            .map(|u| (u.label.clone(), u.get_score()))
            .collect();
        
        // Sort by score descending
        available.sort_by(|a, b| b.1.cmp(&a.1));
        
        available.into_iter().map(|(label, _)| label).collect()
    }
    
    /// Get the single best upstream
    pub fn get_top_upstream(&self) -> Option<String> {
        self.get_best_upstreams().first().cloned()
    }
    
    /// Print all upstream statuses (for debugging/dashboard)
    pub fn status_report(&self) -> Vec<String> {
        self.upstreams.read()
            .iter()
            .map(|u| u.summary())
            .collect()
    }
    
    /// Get number of registered upstreams
    pub fn get_upstream_count(&self) -> usize {
        self.upstreams.read().len()
    }
    
    /// Get all upstreams for API exposure
    pub fn get_all_upstreams(&self) -> Vec<Arc<UpstreamMetrics>> {
        self.upstreams.read().clone()
    }
    
    /// Run periodic health check loop
    pub async fn run_health_loop(&self, shutdown: tokio_util::sync::CancellationToken) {
        info!("🤖 AutoPilot Engine started (check interval: {:?})", self.check_interval);
        
        let mut last_prefetch_hour: u32 = 255; // Invalid hour to trigger first run
        let mut udp_block_counter: u32 = 0;
        let persist_path = get_autopilot_state_path();
        let mut last_persist = Instant::now();
        let mut last_weight_tune = Instant::now() - AUTOPILOT_WEIGHT_TUNE_INTERVAL;
        
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("?? AutoPilot Engine stopping...");
                    if let Some(ref path) = persist_path {
                        if let Err(e) = save_autopilot_snapshot(path) {
                            warn!("?? AutoPilot: Failed to save snapshot on shutdown: {}", e);
                        }
                    }
                    break;
                }
                _ = tokio::time::sleep(self.check_interval) => {
                    self.run_probes().await;
                    
                    // Log status every check
                    for status in self.status_report() {
                        debug!("📊 {}", status);
                    }
                    
                    // === UDP Blocking Detection ===
                    self.check_udp_blocking(&mut udp_block_counter);
                    
                    // === Hourly Predictive Prefetch ===
                    self.check_hourly_prefetch(&mut last_prefetch_hour);

                    // === Dynamic Weight Tuning ===
                    if last_weight_tune.elapsed() >= AUTOPILOT_WEIGHT_TUNE_INTERVAL {
                        if auto_tune_weights() {
                            // weights updated
                        }
                        last_weight_tune = Instant::now();
                    }

                    if let Some(ref path) = persist_path {
                        if last_persist.elapsed() >= AUTOPILOT_PERSIST_INTERVAL {
                            if let Err(e) = save_autopilot_snapshot(path) {
                                warn!("?? AutoPilot: Failed to save snapshot: {}", e);
                            }
                            last_persist = Instant::now();
                        }
                    }
                }
            }
        }
    }
    
    /// Check if all UDP upstreams are failing (possible UDP blocking)
    fn check_udp_blocking(&self, counter: &mut u32) {
        let upstreams = self.upstreams.read();
        
        // Count UDP vs non-UDP upstreams and their health
        let mut udp_total = 0;
        let mut udp_unhealthy = 0;
        let mut has_doh = false;
        
        for upstream in upstreams.iter() {
            if upstream.label.starts_with("udp://") {
                udp_total += 1;
                if !upstream.healthy.load(Ordering::Relaxed) {
                    udp_unhealthy += 1;
                }
            } else if upstream.label.starts_with("https://") || upstream.label.contains("aliapi://") {
                has_doh = true;
            }
        }
        
        // If all UDP upstreams are unhealthy, increment counter
        if udp_total > 0 && udp_unhealthy == udp_total {
            *counter += 1;
            
            if *counter >= 3 {
                warn!("🚨 UDP Blocking detected! All {} UDP upstreams failed for {} checks", 
                      udp_total, counter);
                
                if has_doh {
                    info!("📡 Automatic failover: DoH/AliAPI upstreams available, they will be prioritized");
                } else {
                    warn!("⚠️ No DoH fallback configured! DNS resolution may fail.");
                }
                
                // Emit metric for external monitoring
                UDP_BLOCKED.store(true, Ordering::Relaxed);
            }
        } else {
            // Reset counter if any UDP is healthy
            if *counter > 0 && udp_unhealthy < udp_total {
                info!("✅ UDP connectivity restored ({}/{} healthy)", 
                      udp_total - udp_unhealthy, udp_total);
                UDP_BLOCKED.store(false, Ordering::Relaxed);
            }
            *counter = 0;
        }
    }
    
    /// Check if we need to trigger hourly prefetch
    fn check_hourly_prefetch(&self, last_hour: &mut u32) {
        use std::time::SystemTime;
        
        let current_hour = {
            let secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ((secs / 3600) % 24) as u32
        };
        
        // Trigger prefetch at the start of each new hour
        if current_hour != *last_hour {
            *last_hour = current_hour;
            
            // Get domains with >20% access probability for next hour
            let candidates = HOT_DOMAINS.get_prefetch_candidates(0.2);
            
            if !candidates.is_empty() {
                info!("🔮 Hourly prefetch: {} domains predicted for hour {}", 
                      candidates.len(), current_hour);
                
                // Trigger prefetch
                HOT_DOMAINS.trigger_prefetch(0.2);
            }
        }
    }
    
    /// Probe all registered upstreams
    async fn run_probes(&self) {
        let upstreams = self.upstreams.read().clone();

        for upstream in upstreams {
            // Skip if recently probed (within 5 seconds)
            if upstream.last_probe.read().elapsed() < Duration::from_secs(5) {
                continue;
            }

            let probe_type = match Self::classify_probe_type(&upstream.label) {
                Some(t) => t,
                None => continue, // Skip DoH/aliapi/quic or unknown schemes
            };

            // Spawn probe task
            let metrics = upstream.clone();
            let timeout = self.probe_timeout;

            tokio::spawn(async move {
                let start = Instant::now();
                let result = tokio::time::timeout(
                    timeout,
                    Self::probe_upstream(&metrics.label, probe_type)
                ).await;

                match result {
                    Ok(Ok(())) => {
                        let latency = start.elapsed().as_millis() as u64;
                        metrics.record_probe(Some(latency), probe_type);
                    }
                    Ok(Err(e)) => {
                        debug!("? Probe failed for {}: {}", metrics.label, e);
                        metrics.record_probe(None, probe_type);
                    }
                    Err(_) => {
                        debug!("? Probe timeout for {}", metrics.label);
                        metrics.record_probe(None, probe_type);
                    }
                }
            });
        }
    }

    fn classify_probe_type(label: &str) -> Option<ProbeType> {
        let lower = label.to_lowercase();
        if lower.starts_with("udp://") {
            Some(ProbeType::DnsPing)
        } else if lower.starts_with("tcp://") || lower.starts_with("tls://") {
            Some(ProbeType::TcpConnect)
        } else {
            None
        }
    }

    async fn probe_upstream(label: &str, probe_type: ProbeType) -> anyhow::Result<()> {
        match probe_type {
            ProbeType::DnsPing => Self::probe_udp(label).await,
            ProbeType::TcpConnect => Self::probe_tcp(label).await,
            _ => Ok(()),
        }
    }

    /// Probe a single upstream with DNS ping (query for ".")
    async fn probe_udp(label: &str) -> anyhow::Result<()> {
        // Parse address from label
        let addr_str = label.trim_start_matches("udp://");

        // Skip if contains path or unexpected format
        if addr_str.contains('/') {
            return Ok(());
        }

        // Parse socket address
        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            // === DNS Ping: Query for "." (root zone) ===
            // This is better than TCP connect because it actually tests DNS

            // Build minimal DNS query for "." with type NS
            // Use nanoseconds from epoch and pointer as pseudo-random ID
            use std::time::SystemTime;
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let query_id: u16 = ((nanos ^ (nanos >> 16)) & 0xFFFF) as u16;
            let dns_query = vec![
                // Header
                (query_id >> 8) as u8, (query_id & 0xFF) as u8, // ID
                0x01, 0x00, // Flags: Standard query, RD=1
                0x00, 0x01, // QDCOUNT: 1
                0x00, 0x00, // ANCOUNT: 0
                0x00, 0x00, // NSCOUNT: 0
                0x00, 0x00, // ARCOUNT: 0
                // Question: "." (root)
                0x00,       // Root label (length 0)
                0x00, 0x02, // QTYPE: NS
                0x00, 0x01, // QCLASS: IN
            ];

            // Send UDP query
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            socket.send_to(&dns_query, addr).await?;

            // Wait for response
            let mut buf = [0u8; 512];
            let (len, _) = socket.recv_from(&mut buf).await?;

            // Verify response ID matches
            if len >= 2 && buf[0] == dns_query[0] && buf[1] == dns_query[1] {
                return Ok(());
            }

            anyhow::bail!("DNS response ID mismatch")
        } else {
            // Can't parse, skip probe
            Ok(())
        }
    }

    /// Probe a single upstream with TCP connect
    async fn probe_tcp(label: &str) -> anyhow::Result<()> {
        let addr_str = label
            .trim_start_matches("tcp://")
            .trim_start_matches("tls://");

        // Skip if contains path or unexpected format
        if addr_str.contains('/') {
            return Ok(());
        }

        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            let _ = tokio::net::TcpStream::connect(addr).await?;
            Ok(())
        } else {
            Ok(())
        }
    }
}

// ============== QPS Statistics Tracker ==============

/// Per-second query statistics
pub struct QpsTracker {
    /// Query counts per second (ring buffer, last 60 seconds)
    second_counts: RwLock<VecDeque<(Instant, u64)>>,
    /// Current second's count (atomic for fast increment)
    current_count: AtomicU64,
    /// Last second timestamp
    last_second: RwLock<Instant>,
}

impl QpsTracker {
    pub fn new() -> Self {
        Self {
            second_counts: RwLock::new(VecDeque::with_capacity(60)),
            current_count: AtomicU64::new(0),
            last_second: RwLock::new(Instant::now()),
        }
    }
    
    /// Record a query
    pub fn record_query(&self) {
        let now = Instant::now();
        let last = *self.last_second.read();
        
        // Check if we've moved to a new second
        if now.duration_since(last).as_secs() >= 1 {
            let count = self.current_count.swap(0, Ordering::Relaxed);
            
            let mut counts = self.second_counts.write();
            // Evict old entries (> 60 seconds)
            while counts.len() >= 60 {
                counts.pop_front();
            }
            counts.push_back((last, count));
            
            *self.last_second.write() = now;
        }
        
        self.current_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get current QPS (queries in last second)
    pub fn get_current_qps(&self) -> u64 {
        self.current_count.load(Ordering::Relaxed)
    }
    
    /// Get average QPS over last N seconds
    pub fn get_avg_qps(&self, seconds: usize) -> f64 {
        let counts = self.second_counts.read();
        let n = counts.len().min(seconds);
        
        if n == 0 {
            return self.get_current_qps() as f64;
        }
        
        let sum: u64 = counts.iter().rev().take(n).map(|(_, c)| c).sum();
        sum as f64 / n as f64
    }
    
    /// Get peak QPS in last 60 seconds
    pub fn get_peak_qps(&self) -> u64 {
        let counts = self.second_counts.read();
        counts.iter().map(|(_, c)| *c).max().unwrap_or(0)
    }
    
    /// Get QPS trend (positive = increasing, negative = decreasing)
    pub fn get_trend(&self) -> f64 {
        let counts = self.second_counts.read();
        if counts.len() < 10 {
            return 0.0;
        }
        
        let recent: f64 = counts.iter().rev().take(5).map(|(_, c)| *c as f64).sum::<f64>() / 5.0;
        let older: f64 = counts.iter().rev().skip(5).take(5).map(|(_, c)| *c as f64).sum::<f64>() / 5.0;
        
        if older > 0.0 {
            (recent - older) / older * 100.0 // Percentage change
        } else {
            0.0
        }
    }
}

/// Global QPS tracker
pub static QPS_TRACKER: Lazy<Arc<QpsTracker>> = Lazy::new(|| {
    Arc::new(QpsTracker::new())
});

/// Record a query for QPS tracking
pub fn record_query() {
    QPS_TRACKER.record_query();
}

/// Get current QPS
pub fn get_current_qps() -> u64 {
    QPS_TRACKER.get_current_qps()
}

/// Get average QPS over last N seconds
pub fn get_avg_qps(seconds: usize) -> f64 {
    QPS_TRACKER.get_avg_qps(seconds)
}

// ============== Global Singleton ==============

/// Global AutoPilot instance
pub static AUTOPILOT: Lazy<Arc<AutoPilot>> = Lazy::new(|| {
    Arc::new(AutoPilot::new())
});

/// Global flag indicating UDP is blocked (all UDP upstreams failed)
pub static UDP_BLOCKED: AtomicBool = AtomicBool::new(false);

/// Check if UDP is currently blocked
pub fn is_udp_blocked() -> bool {
    UDP_BLOCKED.load(Ordering::Relaxed)
}

/// Initialize AutoPilot and start background health check loop
pub fn start_autopilot(shutdown: tokio_util::sync::CancellationToken) {
    let ap = AUTOPILOT.clone();

    if let Some(path) = get_autopilot_state_path() {
        if let Some(snapshot) = load_autopilot_snapshot(&path) {
            apply_autopilot_snapshot(snapshot);
            info!("?? AutoPilot: Loaded snapshot from {:?}", path);
        }
    }
    
    tokio::spawn(async move {
        ap.run_health_loop(shutdown).await;
    });
    
    info!("🚀 AutoPilot AIOps Engine initialized");
}

/// Register an upstream for smart routing
pub fn register_upstream(label: &str) -> Arc<UpstreamMetrics> {
    AUTOPILOT.register(label.to_string())
}

/// Record a successful query for an upstream
pub fn record_success(label: &str, latency_ms: u64) {
    if let Some(metrics) = AUTOPILOT.get(label) {
        metrics.record_success(latency_ms);
    }
    // [Level 23] 同时更新 Bandit 状态
    bandit_record_success(label, latency_ms);
}

/// Record a failed query for an upstream
pub fn record_failure(label: &str) {
    if let Some(metrics) = AUTOPILOT.get(label) {
        metrics.record_failure();
    }
    // [Level 23] 同时更新 Bandit 状态
    bandit_record_failure(label);
}

/// Get the best upstream for a query
pub fn get_best_upstream() -> Option<String> {
    AUTOPILOT.get_top_upstream()
}

/// [Level 23] 混合选择：传统评分 + Bandit 探索
/// 自适应探索率：初期 30%，逐渐降低到 5%
pub fn get_best_upstream_with_bandit() -> Option<String> {
    // 获取传统排名
    let ranked = get_ranked_upstreams();
    if ranked.is_empty() {
        return None;
    }

    // 自适应探索率
    let count = EXPLORATION_COUNT.fetch_add(1, Ordering::Relaxed);
    // 探索率从 30% 指数衰减到 5%
    let explore_rate = 0.30 * (-(count as f64) / 10000.0).exp().max(0.05);

    let mut rng = rand::thread_rng();
    let use_bandit = rng.gen_bool(explore_rate);

    if use_bandit {
        // 使用 Bandit 采样
        if let Some((bandit_choice, score)) = bandit_select_best(&ranked) {
            debug!("🎰 Bandit 探索: {} (探索率: {:.1}%, score: {:.3})",
                   bandit_choice, explore_rate * 100.0, score);
            return Some(bandit_choice);
        }
    }

    // 使用传统最优
    ranked.into_iter().next()
}

/// Get all upstreams sorted by score
pub fn get_ranked_upstreams() -> Vec<String> {
    get_ranked_upstreams_for_scope(NetworkScope::Global)
}

/// Get upstreams sorted by score for a network scope
pub fn get_ranked_upstreams_for_scope(scope: NetworkScope) -> Vec<String> {
    let all = AUTOPILOT.get_all_upstreams();
    let mut scoped = filter_upstreams_by_scope(scope, all.clone());
    if scoped.is_empty() {
        scoped = all;
    }

    let mut available: Vec<_> = scoped.iter()
        .filter(|u| u.is_available())
        .map(|u| (u.label.clone(), u.get_score()))
        .collect();

    available.sort_by(|a, b| b.1.cmp(&a.1));
    available.into_iter().map(|(label, _)| label).collect()
}

/// Get health status for all upstreams (for dashboard/API)
pub fn get_health_report() -> Vec<String> {
    AUTOPILOT.status_report()
}

// ============== Phase 4: 深度智能化模块 ==============

/// 网络状况评估
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkScope {
    Global,
    Domestic, // UDP, AliAPI
    Foreign,  // DoH, DoT, DoQ
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkCondition {
    pub avg_jitter_ms: f64,
    pub avg_loss_rate: f64,
    pub congestion_level: u8, // 0-10, 0=完美, 10=严重拥堵
}

fn scope_for_label(label: &str) -> NetworkScope {
    let l = label.to_lowercase();
    if (l.starts_with("udp://") || l.contains("aliapi://"))
        && !l.contains("127.0.0.1")
        && !l.contains("[::1]")
        && !l.contains("localhost")
    {
        return NetworkScope::Domestic;
    }

    if l.starts_with("https://") || l.starts_with("tls://") || l.starts_with("quic://") {
        return NetworkScope::Foreign;
    }

    NetworkScope::Global
}

fn filter_upstreams_by_scope(scope: NetworkScope, all_upstreams: Vec<Arc<UpstreamMetrics>>) -> Vec<Arc<UpstreamMetrics>> {
    if let NetworkScope::Global = scope {
        return all_upstreams;
    }

    all_upstreams
        .into_iter()
        .filter(|u| scope_for_label(&u.label) == scope)
        .collect()
}
impl NetworkCondition {
    /// 基于指定范围的上游统计数据计算当前网络状况
    pub fn calculate(scope: NetworkScope) -> Self {
        let all_upstreams = AUTOPILOT.get_all_upstreams();
        let upstreams = filter_upstreams_by_scope(scope, all_upstreams);
        
        if upstreams.is_empty() {
            return Self {
                avg_jitter_ms: 0.0,
                avg_loss_rate: 0.0,
                congestion_level: 0,
            };
        }
        
        let count = upstreams.len() as f64;
        let avg_jitter = upstreams.iter()
            .map(|m| m.get_jitter_ms() as f64)
            .sum::<f64>() / count;
        
        let avg_loss = upstreams.iter()
            .map(|m| m.get_packet_loss_rate())
            .sum::<f64>() / count;
        
        // 拥堵等级评估
        let congestion_level = match (avg_jitter, avg_loss) {
            (j, l) if j < 5.0 && l < 0.01 => 0,   // 完美
            (j, l) if j < 10.0 && l < 0.02 => 2,  // 优秀
            (j, l) if j < 15.0 && l < 0.05 => 4,  // 良好
            (j, l) if j < 25.0 && l < 0.08 => 6,  // 一般
            (j, l) if j < 35.0 && l < 0.12 => 8,  // 拥堵
            _ => 10,                               // 严重拥堵
        };
        
        Self {
            avg_jitter_ms: avg_jitter,
            avg_loss_rate: avg_loss,
            congestion_level,
        }
    }
    
    /// 根据网络状况推荐策略
    pub fn recommend_strategy(&self) -> &'static str {
        match self.congestion_level {
            0..=3 => "smart",           // 网络良好，省带宽
            4..=6 => "smart_aggressive",// 网络一般，激进 Hedge
            7..=10 => "race",           // 网络拥堵，Race 抢速度
            _ => "smart"
        }
    }
}

/// 获取指定范围的网络状况
pub fn get_network_condition(scope: NetworkScope) -> NetworkCondition {
    NetworkCondition::calculate(scope)
}

fn normalize_weights(mut w: WeightConfig) -> WeightConfig {
    let sum = w.latency_weight + w.jitter_weight + w.success_weight + w.pktloss_weight;
    if sum.abs() < 1e-6 {
        return WeightConfig::default();
    }
    w.latency_weight /= sum;
    w.jitter_weight /= sum;
    w.success_weight /= sum;
    w.pktloss_weight /= sum;
    w
}

fn max_weight_diff(a: &WeightConfig, b: &WeightConfig) -> f64 {
    let d1 = (a.latency_weight - b.latency_weight).abs();
    let d2 = (a.jitter_weight - b.jitter_weight).abs();
    let d3 = (a.success_weight - b.success_weight).abs();
    let d4 = (a.pktloss_weight - b.pktloss_weight).abs();
    d1.max(d2).max(d3).max(d4)
}

fn build_dynamic_weights(network: NetworkCondition, hour: u32) -> WeightConfig {
    // Base profile by congestion
    let mut w = if network.congestion_level >= 7 {
        WeightConfig { latency_weight: 0.25, jitter_weight: 0.15, success_weight: 0.45, pktloss_weight: 0.15 }
    } else if network.congestion_level <= 2 {
        WeightConfig { latency_weight: 0.45, jitter_weight: 0.15, success_weight: 0.30, pktloss_weight: 0.10 }
    } else if network.congestion_level <= 4 {
        WeightConfig { latency_weight: 0.40, jitter_weight: 0.15, success_weight: 0.35, pktloss_weight: 0.10 }
    } else {
        WeightConfig { latency_weight: 0.30, jitter_weight: 0.15, success_weight: 0.40, pktloss_weight: 0.15 }
    };

    // Time-based adjustment (peak hours: 19-23, 12-13)
    if (19..=23).contains(&hour) || (12..=13).contains(&hour) {
        w.success_weight += 0.03;
        w.pktloss_weight += 0.02;
        w.latency_weight -= 0.03;
        w.jitter_weight -= 0.02;
    } else if (0..=6).contains(&hour) {
        // Off-peak: favor latency slightly
        w.latency_weight += 0.03;
        w.success_weight -= 0.02;
        w.pktloss_weight -= 0.01;
    }

    normalize_weights(w)
}

fn auto_tune_weights_for_scope(scope: NetworkScope) -> bool {
    if scope != NetworkScope::Global {
        let scoped = filter_upstreams_by_scope(scope, AUTOPILOT.get_all_upstreams());
        if scoped.is_empty() {
            return false;
        }
    }

    let network = get_network_condition(scope);
    let hour = chrono::Local::now().hour();
    let target = build_dynamic_weights(network, hour);
    let current = get_current_weights_for_scope(scope);

    if max_weight_diff(&current, &target) < 0.02 {
        return false; // No meaningful change
    }

    if let Err(e) = set_weights_for_scope(scope, target.clone()) {
        warn!("?? AutoPilot: Failed to set dynamic weights({:?}): {}", scope, e);
        return false;
    }

    info!(
        "?? AutoPilot: Dynamic weights applied (scope={:?}, hour={}, congestion={}) -> {}",
        scope,
        hour,
        network.congestion_level,
        target.description()
    );
    true
}

fn auto_tune_weights() -> bool {
    let mut changed = false;
    for scope in [NetworkScope::Domestic, NetworkScope::Foreign, NetworkScope::Global] {
        if auto_tune_weights_for_scope(scope) {
            changed = true;
        }
    }
    changed
}
/// 时间感知路由推荐
pub fn get_time_based_recommendation() -> (&'static str, std::time::Duration) {
    let hour = chrono::Local::now().hour();
    
    match hour {
        // 晚高峰 (19:00-23:00): 网络拥堵，用 Race 保证速度
        19..=23 => ("race", std::time::Duration::from_millis(0)),
        
        // 午高峰 (12:00-14:00): 中等拥堵，激进 Hedge
        12..=14 => ("smart", std::time::Duration::from_millis(50)),
        
        // 凌晨低谷 (02:00-06:00): 网络稳定，保守 Hedge 省带宽
        2..=6 => ("smart", std::time::Duration::from_millis(150)),
        
        // 正常时段: 标准 Smart
        _ => ("smart", std::time::Duration::from_millis(100)),
    }
}

/// 预测性故障转移：检测上游是否正在劣化
pub fn is_upstream_degrading(label: &str) -> bool {
    if let Some(metrics) = AUTOPILOT.get(label) {
        // 检查连续失败次数
        let consecutive_failures = metrics.consecutive_failures.load(Ordering::Relaxed);
        if consecutive_failures >= 2 {
            return true;
        }
        
        // 检查最近趋势（最近10次 vs 总体平均）
        let history = metrics.rtt_history.read();
        if history.len() >= 10 {
            let recent_10: Vec<u64> = history.iter().rev().take(10).copied().collect();
            let recent_avg = recent_10.iter().sum::<u64>() as f64 / recent_10.len() as f64;
            let overall_avg = metrics.get_avg_rtt() as f64;
            
            // 如果最近平均 RTT 比总体高 50%，说明正在劣化
            if recent_avg > overall_avg * 1.5 {
                debug!("🔮 预测性切换: {} 正在劣化 (recent={:.0}ms, overall={:.0}ms)", 
                       label, recent_avg, overall_avg);
                return true;
            }
        }
    }
    
    false
}

/// 获取最近 N 次查询的平均 RTT（用于趋势分析）
impl UpstreamMetrics {
    pub fn get_recent_avg_rtt(&self, count: usize) -> u64 {
        let history = self.rtt_history.read();
        if history.is_empty() {
            return self.avg_rtt_ms.load(Ordering::Relaxed);
        }
        
        let recent: Vec<u64> = history.iter().rev().take(count).copied().collect();
        if recent.is_empty() {
            return self.avg_rtt_ms.load(Ordering::Relaxed);
        }
        
        recent.iter().sum::<u64>() / recent.len() as u64
    }
}

// ============== Level 1: AI 学习 - 域名级记忆 (优化版) ==============

/// 域名记忆最大容量
const MAX_DOMAIN_MEMORY: usize = 10000;

/// 基础过期时间 (1小时)
const DOMAIN_MEMORY_BASE_TTL: u64 = 3600;

/// 热门域名延长因子 (成功次数 * 系数 = 额外秒数，最大延长到24小时)
const DOMAIN_MEMORY_HOT_FACTOR: u64 = 600; // 每成功1次多保留10分钟

/// 域名记忆学习阈值（放宽以提高命中率）
const DOMAIN_MEMORY_MAX_LATENCY_MS: u64 = 80;
const CLIENT_MEMORY_MAX_LATENCY_MS: u64 = 120;
const DOMAIN_MEMORY_CONFIDENCE: u32 = 2;

/// 域名记忆条目：记录历史最优上游
#[derive(Debug, Clone)]
pub struct DomainMemory {
    /// 最优上游标签
    pub best_upstream: String,
    /// 平均延迟 (ms)
    pub avg_latency: u64,
    /// 成功次数（置信度）
    pub success_count: u32,
    /// 最后更新时间
    pub last_update: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainMemorySnapshot {
    pub best_upstream: String,
    pub avg_latency: u64,
    pub success_count: u32,
    pub age_secs: u64,
}

impl DomainMemory {
    fn new(upstream: String, latency: u64) -> Self {
        Self {
            best_upstream: upstream,
            avg_latency: latency,
            success_count: 1,
            last_update: Instant::now(),
        }
    }
    
    fn to_snapshot(&self) -> DomainMemorySnapshot {
        DomainMemorySnapshot {
            best_upstream: self.best_upstream.clone(),
            avg_latency: self.avg_latency,
            success_count: self.success_count,
            age_secs: self.last_update.elapsed().as_secs(),
        }
    }

    fn from_snapshot(snapshot: DomainMemorySnapshot) -> Self {
        Self {
            best_upstream: snapshot.best_upstream,
            avg_latency: snapshot.avg_latency,
            success_count: snapshot.success_count,
            last_update: Instant::now() - Duration::from_secs(snapshot.age_secs),
        }
    }

    /// 更新记录（移动平均）
    fn update(&mut self, upstream: String, latency: u64) {
        if upstream == self.best_upstream {
            // 相同上游，更新延迟（移动平均）
            self.avg_latency = (self.avg_latency * self.success_count as u64 + latency) 
                             / (self.success_count + 1) as u64;
            self.success_count += 1;
        } else {
            // 不同上游，如果更快则替换
            if latency < self.avg_latency {
                self.best_upstream = upstream;
                self.avg_latency = latency;
                self.success_count = 1;
            }
        }
        self.last_update = Instant::now();
    }
    
    /// 是否过期 (LRU优化: 热门域名延长保留)
    fn is_expired(&self) -> bool {
        // 热门域名延长保留: 每成功1次多保留10分钟，最多24小时
        let bonus_secs = (self.success_count as u64 * DOMAIN_MEMORY_HOT_FACTOR).min(86400 - DOMAIN_MEMORY_BASE_TTL);
        let ttl = DOMAIN_MEMORY_BASE_TTL + bonus_secs;
        self.last_update.elapsed() > Duration::from_secs(ttl)
    }
    
    /// 获取有效期剩余时间 (用于LRU排序)
    fn remaining_ttl(&self) -> i64 {
        let bonus_secs = (self.success_count as u64 * DOMAIN_MEMORY_HOT_FACTOR).min(86400 - DOMAIN_MEMORY_BASE_TTL);
        let ttl = DOMAIN_MEMORY_BASE_TTL + bonus_secs;
        ttl as i64 - self.last_update.elapsed().as_secs() as i64
    }
    
    /// 是否足够可信（至少成功2次）
    fn is_confident(&self) -> bool {
        self.success_count >= DOMAIN_MEMORY_CONFIDENCE
    }
}

/// 全局域名记忆表
static DOMAIN_MEMORY: Lazy<DashMap<String, DomainMemory>> = Lazy::new(DashMap::new);

/// 记录域名查询结果（AI 学习）
pub fn record_domain_result(domain: &str, upstream: &str, latency_ms: u64) {
    // 只记录快速响应（阈值内），避免记录慢速查询
    if latency_ms > DOMAIN_MEMORY_MAX_LATENCY_MS {
        return;
    }
    
    // 规范化域名（转小写）
    let domain_lower = domain.to_lowercase();
    
    if let Some(mut entry) = DOMAIN_MEMORY.get_mut(&domain_lower) {
        entry.update(upstream.to_string(), latency_ms);
    } else {
        DOMAIN_MEMORY.insert(domain_lower, DomainMemory::new(upstream.to_string(), latency_ms));
    }
    
    // 定期清理过期条目（每添加100条时检查）
    if DOMAIN_MEMORY.len() % 100 == 0 {
        cleanup_expired_domains();
    }
}

/// 获取域名的历史最优上游（AI 推荐）
pub fn get_domain_best_upstream(domain: &str) -> Option<String> {
    let domain_lower = domain.to_lowercase();
    
    if let Some(entry) = DOMAIN_MEMORY.get(&domain_lower) {
        // 检查是否过期
        if entry.is_expired() {
            drop(entry);  // 释放读锁
            DOMAIN_MEMORY.remove(&domain_lower);
            return None;
        }
        
        // 只在足够可信时返回推荐
        if entry.is_confident() {
            debug!("💡 AI推荐: {} → {} ({}ms, 成功{}次)", 
                   domain, entry.best_upstream, entry.avg_latency, entry.success_count);
            return Some(entry.best_upstream.clone());
        }
    }
    
    None
}

/// 清理过期的域名记忆 (LRU优化版)
fn cleanup_expired_domains() {
    // 1. 先清理过期条目
    DOMAIN_MEMORY.retain(|_, v| !v.is_expired());
    
    // 2. 如果仍超出容量限制，淘汰剩余TTL最短的
    if DOMAIN_MEMORY.len() > MAX_DOMAIN_MEMORY {
        let excess = DOMAIN_MEMORY.len() - MAX_DOMAIN_MEMORY;
        
        // 收集所有条目并按剩余TTL排序
        let mut entries: Vec<_> = DOMAIN_MEMORY.iter()
            .map(|e| (e.key().clone(), e.remaining_ttl()))
            .collect();
        entries.sort_by_key(|(_, ttl)| *ttl); // 升序，TTL最短的在前
        
        // 淘汰TTL最短的
        for (domain, _) in entries.into_iter().take(excess) {
            DOMAIN_MEMORY.remove(&domain);
        }
        
        debug!("🧹 域名记忆LRU淘汰: 删除 {} 条最冷门条目", excess);
    }
    
    debug!("🧹 域名记忆清理完成: 剩余 {} 条", DOMAIN_MEMORY.len());
}

/// 获取域名记忆统计
pub fn get_domain_memory_stats() -> (usize, usize) {
    let total = DOMAIN_MEMORY.len();
    let confident = DOMAIN_MEMORY.iter().filter(|e| e.is_confident()).count();
    (total, confident)
}

// ============== Level 13: 客户端感知学习 ==============

/// 客户端感知的域名记忆 (domain@subnet -> best_upstream)
/// 例如: "baidu.com@192.168.1" -> "223.5.5.5"
static CLIENT_DOMAIN_MEMORY: Lazy<DashMap<String, DomainMemory>> = Lazy::new(DashMap::new);

/// 最大客户端记忆容量
const MAX_CLIENT_MEMORY: usize = 5000;

/// 从 IP 地址提取子网前缀 (用于区分不同网络的客户端)
pub fn get_client_subnet(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 对于内网地址，使用前3段作为子网标识
            if octets[0] == 10 || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) 
               || (octets[0] == 192 && octets[1] == 168) {
                format!("{}.{}.{}", octets[0], octets[1], octets[2])
            } else {
                // 对于公网地址，使用前2段 (更粗粒度)
                format!("{}.{}", octets[0], octets[1])
            }
        }
        std::net::IpAddr::V6(v6) => {
            // IPv6 使用前 48 位作为标识
            let segments = v6.segments();
            format!("{:x}:{:x}:{:x}", segments[0], segments[1], segments[2])
        }
    }
}

/// 生成客户端感知的记忆 Key
fn client_memory_key(domain: &str, client_ip: std::net::IpAddr) -> String {
    format!("{}@{}", domain.to_lowercase(), get_client_subnet(client_ip))
}

/// 记录域名查询结果（客户端感知版）
pub fn record_domain_result_for_client(domain: &str, upstream: &str, latency_ms: u64, client_ip: std::net::IpAddr) {
    // 只记录快速响应（阈值内）
    if latency_ms > CLIENT_MEMORY_MAX_LATENCY_MS {
        return;
    }
    
    let key = client_memory_key(domain, client_ip);
    
    CLIENT_DOMAIN_MEMORY.entry(key.clone())
        .and_modify(|entry| {
            entry.update(upstream.to_string(), latency_ms);
        })
        .or_insert(DomainMemory::new(upstream.to_string(), latency_ms));
    
    // 定期清理
    if CLIENT_DOMAIN_MEMORY.len() % 100 == 0 {
        cleanup_client_memory();
    }
    
    // 同时更新全局记忆（向后兼容）
    record_domain_result(domain, upstream, latency_ms);
}

/// 获取域名的历史最优上游（客户端感知版）
pub fn get_domain_best_upstream_for_client(domain: &str, client_ip: std::net::IpAddr) -> Option<String> {
    let key = client_memory_key(domain, client_ip);
    
    // 优先查找客户端特定记忆
    if let Some(entry) = CLIENT_DOMAIN_MEMORY.get(&key) {
        if !entry.is_expired() && entry.is_confident() {
            let subnet = get_client_subnet(client_ip);
            debug!("💡 AI推荐(客户端感知): {}@{} → {} ({}ms, 成功{}次)", 
                   domain, subnet, entry.best_upstream, entry.avg_latency, entry.success_count);
            return Some(entry.best_upstream.clone());
        }
    }
    
    // 回退到全局记忆
    get_domain_best_upstream(domain)
}

/// 清理客户端记忆
fn cleanup_client_memory() {
    CLIENT_DOMAIN_MEMORY.retain(|_, v| !v.is_expired());
    
    // 容量限制
    if CLIENT_DOMAIN_MEMORY.len() > MAX_CLIENT_MEMORY {
        let excess = CLIENT_DOMAIN_MEMORY.len() - MAX_CLIENT_MEMORY;
        let mut entries: Vec<_> = CLIENT_DOMAIN_MEMORY.iter()
            .map(|e| (e.key().clone(), e.remaining_ttl()))
            .collect();
        entries.sort_by_key(|(_, ttl)| *ttl);
        
        for (key, _) in entries.into_iter().take(excess) {
            CLIENT_DOMAIN_MEMORY.remove(&key);
        }
    }
}

/// 获取客户端感知记忆统计
pub fn get_client_memory_stats() -> (usize, usize) {
    let total = CLIENT_DOMAIN_MEMORY.len();
    let confident = CLIENT_DOMAIN_MEMORY.iter().filter(|e| e.is_confident()).count();
    (total, confident)
}

// ============== Level 2: AI 学习 - 查询模式预测 ==============

/// 域名关联表：记录 A 之后经常查询 B
static DOMAIN_FOLLOWS: Lazy<DashMap<String, DashMap<String, u32>>> = Lazy::new(DashMap::new);

/// 最近查询记录（用于关联分析）
static LAST_QUERY: Lazy<RwLock<Option<(String, Instant)>>> = Lazy::new(|| RwLock::new(None));

/// 记录查询序列（用于学习关联规则）
pub fn record_query_sequence(domain: &str) {
    let domain_lower = domain.to_lowercase();
    let now = Instant::now();
    
    // 获取上一次查询
    let last = {
        let guard = LAST_QUERY.read();
        guard.clone()
    };
    
    // 如果上一次查询在5秒内，记录关联
    if let Some((prev_domain, prev_time)) = last {
        if now.duration_since(prev_time) < Duration::from_secs(5) && prev_domain != domain_lower {
            // 记录: prev_domain -> domain_lower
            let follows = DOMAIN_FOLLOWS.entry(prev_domain).or_insert_with(DashMap::new);
            let mut count = follows.entry(domain_lower.clone()).or_insert(0);
            *count.value_mut() += 1;
        }
    }
    
    // 更新最近查询
    *LAST_QUERY.write() = Some((domain_lower, now));
    
    // 定期清理（每1000次）
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    if COUNTER.fetch_add(1, Ordering::Relaxed) % 1000 == 0 {
        cleanup_weak_associations();
    }
}

/// 获取预测的下一个查询（用于预热）
pub fn predict_next_queries(domain: &str, top_n: usize) -> Vec<String> {
    let domain_lower = domain.to_lowercase();
    
    if let Some(follows) = DOMAIN_FOLLOWS.get(&domain_lower) {
        let mut predictions: Vec<(String, u32)> = follows
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        
        // 按频率排序
        predictions.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 只返回高频关联（至少3次）
        predictions.into_iter()
            .filter(|(_, count)| *count >= 3)
            .take(top_n)
            .map(|(d, _)| d)
            .collect()
    } else {
        Vec::new()
    }
}

/// 清理弱关联（出现次数<2的）
fn cleanup_weak_associations() {
    DOMAIN_FOLLOWS.retain(|_, follows| {
        follows.retain(|_, count| *count >= 2);
        !follows.is_empty()
    });
    debug!("🧹 关联规则清理: 剩余 {} 条主规则", DOMAIN_FOLLOWS.len());
}

/// 获取查询预测统计
pub fn get_prediction_stats() -> (usize, usize) {
    let total_rules = DOMAIN_FOLLOWS.len();
    let total_associations: usize = DOMAIN_FOLLOWS.iter()
        .map(|e| e.value().len())
        .sum();
    (total_rules, total_associations)
}

// ============== Level 12: 域名难度学习 ==============

/// 域名难度记录
#[derive(Debug, Clone)]
struct DomainDifficulty {
    /// 失败次数
    failure_count: u32,
    /// 总尝试次数
    total_attempts: u32,
    /// 平均需要的尝试次数才能成功
    avg_attempts_to_success: f32,
    /// 最后更新时间
    last_update: Instant,
}

/// 全局域名难度表
static DOMAIN_DIFFICULTY: Lazy<DashMap<String, DomainDifficulty>> = Lazy::new(DashMap::new);

/// 记录域名查询尝试 (成功或失败)
pub fn record_domain_attempt(domain: &str, success: bool, attempts: u32) {
    let domain_lower = domain.to_lowercase();
    
    DOMAIN_DIFFICULTY.entry(domain_lower)
        .and_modify(|d| {
            d.total_attempts += 1;
            if !success {
                d.failure_count += 1;
            }
            // 更新平均尝试次数 (移动平均)
            d.avg_attempts_to_success = d.avg_attempts_to_success * 0.8 + attempts as f32 * 0.2;
            d.last_update = Instant::now();
        })
        .or_insert(DomainDifficulty {
            failure_count: if success { 0 } else { 1 },
            total_attempts: 1,
            avg_attempts_to_success: attempts as f32,
            last_update: Instant::now(),
        });
}

/// 获取域名的"难度等级" (0-5, 0=容易, 5=非常困难)
pub fn get_domain_difficulty(domain: &str) -> u8 {
    let domain_lower = domain.to_lowercase();
    
    if let Some(d) = DOMAIN_DIFFICULTY.get(&domain_lower) {
        // 过期检查 (1小时)
        if d.last_update.elapsed() > Duration::from_secs(3600) {
            return 0;
        }
        
        // 计算难度分数
        let failure_rate = if d.total_attempts > 0 {
            d.failure_count as f32 / d.total_attempts as f32
        } else {
            0.0
        };
        
        // 难度 = 失败率 * 3 + 平均尝试次数权重
        let score = failure_rate * 3.0 + (d.avg_attempts_to_success - 1.0).max(0.0) * 0.5;
        
        (score.min(5.0) as u8).min(5)
    } else {
        0 // 未知域名默认容易
    }
}

/// 获取域名难度带来的并发数加成
pub fn get_difficulty_concurrency_boost(domain: &str) -> usize {
    match get_domain_difficulty(domain) {
        0 => 0,     // 容易: 不加
        1 => 0,     // 轻微: 不加
        2 => 1,     // 中等: +1
        3 => 1,     // 较难: +1
        4 => 2,     // 困难: +2
        5 => 3,     // 非常困难: +3
        _ => 0,
    }
}

/// 清理过期的域名难度记录
fn cleanup_domain_difficulty() {
    DOMAIN_DIFFICULTY.retain(|_, d| d.last_update.elapsed() < Duration::from_secs(3600));
}

// ============== Level 3: AI 自愈 - 健康诊断与自动恢复 ==============

/// 系统健康状态
#[derive(Debug, Clone)]
pub struct HealthDiagnosis {
    pub overall_score: u8,      // 0-100
    pub issues: Vec<HealthIssue>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HealthIssue {
    pub severity: u8,           // 1-10
    pub category: &'static str,
    pub description: String,
}

impl HealthDiagnosis {
    /// 执行全面健康诊断
    pub fn run() -> Self {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();
        
        let upstreams = AUTOPILOT.get_all_upstreams();
        
        // 检查1: 上游健康状态
        let healthy_count = upstreams.iter().filter(|u| u.healthy.load(Ordering::Relaxed)).count();
        let total_count = upstreams.len();
        
        if total_count == 0 {
            issues.push(HealthIssue {
                severity: 10,
                category: "upstream",
                description: "无上游服务器配置".to_string(),
            });
            recommendations.push("添加至少一个上游DNS服务器".to_string());
        } else if healthy_count == 0 {
            issues.push(HealthIssue {
                severity: 10,
                category: "upstream",
                description: "所有上游都不可用".to_string(),
            });
            recommendations.push("检查网络连接".to_string());
            recommendations.push("考虑添加备用上游".to_string());
        } else if healthy_count < total_count / 2 {
            issues.push(HealthIssue {
                severity: 7,
                category: "upstream",
                description: format!("过半上游不可用 ({}/{})", total_count - healthy_count, total_count),
            });
            recommendations.push("检查失败上游的网络状况".to_string());
        }
        
        // 检查2: 高延迟上游
        for u in &upstreams {
            let avg_rtt = u.avg_rtt_ms.load(Ordering::Relaxed);
            if avg_rtt > 200 {
                issues.push(HealthIssue {
                    severity: 5,
                    category: "latency",
                    description: format!("{} 延迟过高 ({}ms)", u.label, avg_rtt),
                });
            }
        }
        
        // 检查3: 高丢包率
        for u in &upstreams {
            let loss_rate = u.get_packet_loss_rate();
            if loss_rate > 0.1 {
                issues.push(HealthIssue {
                    severity: 6,
                    category: "packet_loss",
                    description: format!("{} 丢包率过高 ({:.1}%)", u.label, loss_rate * 100.0),
                });
                recommendations.push(format!("考虑移除不稳定上游: {}", u.label));
            }
        }
        
        // 检查4: 网络拥堵
        let network = NetworkCondition::calculate(NetworkScope::Global);
        if network.congestion_level >= 7 {
            issues.push(HealthIssue {
                severity: 7,
                category: "network",
                description: format!("网络拥堵严重 (等级: {}/10)", network.congestion_level),
            });
            recommendations.push("建议切换到 Race 策略".to_string());
        }
        
        // 计算总分
        let max_severity: u8 = issues.iter().map(|i| i.severity).max().unwrap_or(0);
        let overall_score = 100 - max_severity * 10;
        
        Self {
            overall_score,
            issues,
            recommendations,
        }
    }
    
    /// 获取状态描述
    pub fn status(&self) -> &'static str {
        match self.overall_score {
            90..=100 => "健康",
            70..=89 => "良好",
            50..=69 => "一般",
            30..=49 => "警告",
            _ => "危险",
        }
    }
}

/// 执行健康诊断并记录
pub fn diagnose_health() -> HealthDiagnosis {
    let diagnosis = HealthDiagnosis::run();
    
    if !diagnosis.issues.is_empty() {
        warn!("🏥 健康诊断: {} (分数: {})", diagnosis.status(), diagnosis.overall_score);
        for issue in &diagnosis.issues {
            warn!("   ⚠️ [{}] {}", issue.category, issue.description);
        }
        for rec in &diagnosis.recommendations {
            info!("   💡 建议: {}", rec);
        }
    } else {
        debug!("🏥 健康诊断: 系统正常 (分数: 100)");
    }
    
    diagnosis
}

// ============== Level 6: AI 安全 - DNS 污染检测 ==============

use std::net::IpAddr;



/// 判断是否应该预热（高峰前15分钟）
pub fn should_prefetch_for_peak() -> bool {
    let hour = chrono::Local::now().hour();
    let minute = chrono::Local::now().minute();
    
    // 晚高峰前15分钟 (18:45-19:00)
    (hour == 18 && minute >= 45) ||
    // 午高峰前15分钟 (11:45-12:00)
    (hour == 11 && minute >= 45) ||
    // 早高峰前15分钟 (07:45-08:00)
    (hour == 7 && minute >= 45)
}

/// 记录域名查询（复用已有的 track_domain）
pub fn record_domain_query(domain: &str) {
    track_domain(domain);
}

// ============== Level 8: 上游评级展示 ==============

/// 上游评级信息
#[derive(Debug, Clone)]
pub struct UpstreamRanking {
    pub rank: u32,
    pub label: String,
    pub score: u64,
    pub avg_latency_ms: u64,
    pub success_rate: f64,
    pub packet_loss: f64,
    pub status: &'static str,
}

/// 获取上游排名（按综合评分排序）
pub fn get_upstream_rankings() -> Vec<UpstreamRanking> {
    let upstreams = AUTOPILOT.get_all_upstreams();
    
    let mut rankings: Vec<_> = upstreams.iter().map(|u| {
        let healthy = u.healthy.load(Ordering::Relaxed);
        UpstreamRanking {
            rank: 0,
            label: u.label.clone(),
            score: u.get_score(),
            avg_latency_ms: u.avg_rtt_ms.load(Ordering::Relaxed),
            success_rate: u.get_success_rate(),
            packet_loss: u.get_packet_loss_rate(),
            status: if healthy { "🟢 健康" } else { "🔴 离线" },
        }
    }).collect();
    
    // 按评分排序
    rankings.sort_by(|a, b| b.score.cmp(&a.score));
    
    // 设置排名
    for (i, r) in rankings.iter_mut().enumerate() {
        r.rank = (i + 1) as u32;
    }
    
    rankings
}

/// 打印上游排名报告
pub fn print_upstream_report() {
    let rankings = get_upstream_rankings();
    
    info!("📊 ============ 上游服务器排名 ============");
    for r in &rankings {
        info!("  #{} {} [{}] 分数:{} 延迟:{}ms 成功率:{:.1}% 丢包:{:.1}%",
              r.rank, r.status, r.label, r.score, r.avg_latency_ms, 
              r.success_rate * 100.0, r.packet_loss * 100.0);
    }
    info!("📊 ==========================================");
}

// ============== Level 9: 优化建议 ==============

/// 生成优化建议
pub fn generate_optimization_suggestions() -> Vec<String> {
    let mut suggestions = Vec::new();
    let rankings = get_upstream_rankings();
    let diagnosis = HealthDiagnosis::run();
    
    // 1. 检查是否有低延迟上游未被充分利用
    if let Some(best) = rankings.first() {
        if best.avg_latency_ms < 10 && best.score < 800 {
            suggestions.push(format!(
                "💡 {} 延迟很低({}ms)但评分不高，可能存在不稳定问题",
                best.label, best.avg_latency_ms
            ));
        }
    }
    
    // 2. 检查高丢包率上游
    for r in &rankings {
        if r.packet_loss > 0.1 {
            suggestions.push(format!(
                "⚠️ {} 丢包率过高({:.1}%)，建议检查网络或移除",
                r.label, r.packet_loss * 100.0
            ));
        }
    }
    
    // 3. 检查是否所有上游都是同一个
    let unique_prefixes: std::collections::HashSet<_> = rankings.iter()
        .map(|r| r.label.split('/').nth(2).unwrap_or(&r.label))
        .collect();
    if unique_prefixes.len() == 1 && rankings.len() > 1 {
        suggestions.push("💡 所有上游都来自同一提供商，建议增加多样性".to_string());
    }
    
    // 4. 根据健康诊断添加建议
    for rec in diagnosis.recommendations {
        suggestions.push(format!("🏥 {}", rec));
    }
    
    // 5. 域名记忆状态
    let (total, confident) = get_domain_memory_stats();
    if total > 100 && confident < total / 10 {
        suggestions.push(format!(
            "📝 域名记忆: {}/{}条可信，学习效果待提升",
            confident, total
        ));
    }
    
    suggestions
}

// ============== Level 4: 自动调参 ==============

/// 计算自适应 Hedge Delay
pub fn get_adaptive_hedge_delay(primary_label: &str) -> Duration {
    // 获取 Primary 上游的指标
    let upstreams = AUTOPILOT.get_all_upstreams();
    if let Some(upstream) = upstreams.iter().find(|u| u.label == primary_label) {
        let p95 = upstream.get_p95_latency();
        let jitter = upstream.jitter_ms.load(Ordering::Relaxed);
        
        // 核心公式: Hedge = P95 + (Jitter * 2)
        // 逻辑: 我们期望95%的请求在P95时间内完成。
        // 如果网络波动(Jitter)大，我们要多给点缓冲时间，避免发送不必要的Hedge包。
        let adaptive_delay = p95 + (jitter * 2);
        
        // 限制范围: [10ms, 300ms]
        // 低于10ms太激进，容易风暴；高于300ms太慢，影响体验。
        let final_delay = adaptive_delay.max(10).min(300);
        
        debug!("🎛️ Adaptive Hedge for {}: P95={} + Jitter({})*2 = {}ms", 
               primary_label, p95, jitter, final_delay);
               
        return Duration::from_millis(final_delay);
    }
    
    // 默认值
    Duration::from_millis(150)
}

/// 打印优化建议
pub fn print_optimization_suggestions() {
    let suggestions = generate_optimization_suggestions();
    
    if suggestions.is_empty() {
        info!("✅ 系统运行良好，暂无优化建议");
    } else {
        info!("🔧 ============ 优化建议 ============");
        for s in &suggestions {
            info!("  {}", s);
        }
        info!("🔧 ====================================");
    }
}

// ============== Level 5.2: 智能 TTL (基于稳定性) ==============

/// 域名稳定性记录
#[derive(Debug, Clone)]
struct IPStability {
    last_ips: Vec<IpAddr>,
    stable_count: u32,       // 连续保持不变的次数
    last_change: Instant,    // 上次变动时间
    original_ttl_avg: u32,
}

static STABILITY_RECORDS: Lazy<DashMap<String, IPStability>> = Lazy::new(DashMap::new);

/// 记录解析结果并分析稳定性
pub fn analyze_domain_stability(domain: &str, ips: Vec<IpAddr>, ttl: u32) {
    let domain_lower = domain.to_lowercase();
    // 排序以忽略顺序差异
    let mut sorted_ips = ips.clone();
    sorted_ips.sort();
    
    STABILITY_RECORDS.entry(domain_lower)
        .and_modify(|s| {
            if s.last_ips == sorted_ips {
                // IP 没变，稳定性+1
                s.stable_count = s.stable_count.saturating_add(1);
            } else {
                // IP 变了，稳定性重置
                // 只有当积累了一定稳定性突然变化时才警告
                if s.stable_count > 10 {
                    debug!("📉 域名 {} IP发生变更，重置稳定性", domain);
                }
                s.stable_count = 0;
                s.last_ips = sorted_ips.clone();
                s.last_change = Instant::now();
            }
            // 更新平均TTL (简单的移动平均)
            s.original_ttl_avg = (s.original_ttl_avg + ttl) / 2;
        })
        .or_insert(IPStability {
            last_ips: sorted_ips,
            stable_count: 0,
            last_change: Instant::now(),
            original_ttl_avg: ttl,
        });
}

/// 获取推荐的智能 TTL
/// 返回: Some(new_ttl) 如果建议修改; None 如果保持原样
pub fn get_smart_ttl(domain: &str, current_ttl: u32) -> Option<u32> {
    if let Some(record) = STABILITY_RECORDS.get(&domain.to_lowercase()) {
        // 策略:
        // 1. 只有连续 5 次查询 IP 没变
        // 2. 且 IP 至少保持了 10 分钟没变
        // 3. 原 TTL 比较短 (< 300s)
        if record.stable_count >= 5 && 
           record.last_change.elapsed() > Duration::from_secs(600) &&
           current_ttl < 300 {
            
            // 智能延长:
            // 如果非常稳定 (1小时没变, >20次), 延长到 3600s
            // 否则延长到 600s
            let target_ttl = if record.stable_count > 20 && record.last_change.elapsed() > Duration::from_secs(3600) {
                3600
            } else {
                600
            };
            
            // 只有当目标 TTL 大于当前 TTL 时才修改
            if target_ttl > current_ttl {
                debug!("🧠 SmartTTL: 延长 {} TTL: {}s -> {}s (稳定系数: {})", 
                       domain, current_ttl, target_ttl, record.stable_count);
                return Some(target_ttl);
            }
        }
    }
    None
}



// ============== Level 6.1: AI 安全 - DNS 污染检测 ==============

static KNOWN_POISON_IPS: Lazy<std::collections::HashSet<IpAddr>> = Lazy::new(|| {
    let mut s = std::collections::HashSet::new();
    // 本地回环和全零通常不应作为公网解析结果
    if let Ok(ip) = "127.0.0.1".parse() { s.insert(ip); }
    if let Ok(ip) = "0.0.0.0".parse() { s.insert(ip); }
    
    // 常见污染 IP 列表 (示例)
    let bad_ips = [
        "243.185.187.39", "46.82.174.68", "37.61.54.158", "93.46.8.89",
        "59.24.3.173", "203.98.7.65", "8.7.198.45", "78.16.49.15", "159.106.121.75"
    ];
    for ip_str in bad_ips.iter() {
        if let Ok(ip) = ip_str.parse() { s.insert(ip); }
    }
    s
});

/// 检查 IP 是否为已知污染源
pub fn is_known_poison_ip(ip: &IpAddr) -> bool {
    let is_poison = KNOWN_POISON_IPS.contains(ip);
    if is_poison {
        warn!("☣️ 检测到 DNS 污染 IP: {}", ip);
    }
    is_poison
}

// ============== Level 7: AI 安全 - DGA 检测 ==============

/// DGA 检测结果
#[derive(Debug, Clone)]
pub struct DgaResult {
    pub is_dga: bool,
    pub score: f64,
    pub reason: &'static str,
}

/// 计算字符串的香农熵
fn calculate_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let len = s.len() as f64;
    
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// 检查是否为 DGA 恶意域名
pub fn detect_dga_domain(domain: &str) -> DgaResult {
    // 忽略顶级域 (TLD)
    let clean = domain.trim_end_matches('.');
    let mut iter = clean.rsplit('.');
    let _tld = iter.next();
    let sld = match iter.next() {
        Some(s) if !s.is_empty() => s,
        _ => return DgaResult { is_dga: false, score: 0.0, reason: "short" },
    };
    
    // 1. 长度检查: 太短通常不是 DGA
    if sld.len() < 6 {
        return DgaResult { is_dga: false, score: 0.0, reason: "short_sld" };
    }
    
    // 2. 熵值检查
    let entropy = calculate_entropy(sld);
    
    // 3. 数字比例
    let digit_count = sld.chars().filter(|c| c.is_digit(10)).count();
    let digit_ratio = digit_count as f64 / sld.len() as f64;
    
    // 4. 辅音比例 (Consonant Ratio)
    let vowels = "aeiou";
    let consonant_count = sld.chars()
        .filter(|c| c.is_alphabetic() && !vowels.contains(*c))
        .count();
    let consonant_ratio = consonant_count as f64 / sld.len() as f64;
    
    // 综合判定
    // 熵值 > 3.8 且长度 > 10 -> 高风险
    // 辅音比例 > 0.8 (如 "gxkqz") -> 高风险
    if entropy > 4.2 {
        return DgaResult { is_dga: true, score: entropy, reason: "high_entropy" };
    }
    
    if consonant_ratio > 0.85 {
        return DgaResult { is_dga: true, score: consonant_ratio, reason: "high_consonant" };
    }
    
    if sld.len() > 12 && entropy > 3.8 && digit_ratio > 0.3 {
        return DgaResult { is_dga: true, score: entropy, reason: "mixed_high_entropy" };
    }
    
    DgaResult { is_dga: false, score: entropy, reason: "normal" }
}



// ============== Level 7.1: AI 安全 - 智能 DDoS 检测 ==============

/// 客户端行为统计
#[derive(Debug, Clone)]
struct ClientStats {
    total_queries: u64,
    nxdomain_count: u64,
    start_time: Instant,
    last_query: Instant,
    suspicion_score: f64,
    is_blocked: bool,
}

static CLIENT_STATS: Lazy<DashMap<IpAddr, ClientStats>> = Lazy::new(DashMap::new);

/// 分析客户端请求行为
/// 返回: true 如果应该拦截; false 如果放行
pub fn analyze_client_behavior(client_ip: IpAddr, is_nxdomain: bool) -> bool {
    // 白名单本地回环
    if client_ip.is_loopback() {
        return false;
    }

    let mut should_block = false;
    
    CLIENT_STATS.entry(client_ip)
        .and_modify(|stats| {
            // 如果已经被封禁，检查是否过期 (例如封禁 5 分钟)
            if stats.is_blocked {
                if stats.last_query.elapsed() > Duration::from_secs(300) {
                    // 解封
                    stats.is_blocked = false;
                    stats.total_queries = 0;
                    stats.nxdomain_count = 0;
                    stats.start_time = Instant::now();
                    stats.suspicion_score = 0.0;
                    info!("🔓 Client {} 已自动解封", client_ip);
                } else {
                    stats.last_query = Instant::now();
                    should_block = true;
                    return;
                }
            }
            
            // 更新统计
            stats.total_queries += 1;
            if is_nxdomain {
                stats.nxdomain_count += 1;
            }
            stats.last_query = Instant::now();
            
            // 每 100 次查询评估一次，或者 NXDOMAIN 激增时评估
            if stats.total_queries % 50 == 0 || (is_nxdomain && stats.nxdomain_count % 20 == 0) {
                let duration = stats.start_time.elapsed().as_secs_f64();
                if duration < 1.0 { return; } // 时间太短不评估
                
                let qps = stats.total_queries as f64 / duration;
                let nx_ratio = stats.nxdomain_count as f64 / stats.total_queries as f64;
                
                // 判定规则 1: NXDOMAIN 洪水 (QPS > 10 且 NXDOMAIN > 80%)
                if qps > 10.0 && nx_ratio > 0.8 {
                    stats.suspicion_score += 50.0;
                    warn!("⚠️ Client {} 疑似 NXDOMAIN 攻击 (QPS={:.1}, NX={:.1}%)", client_ip, qps, nx_ratio * 100.0);
                }
                
                // 判定规则 2: 高频暴力请求 (QPS > 100)
                if qps > 100.0 {
                    stats.suspicion_score += 20.0;
                }
                
                // 封禁阈值
                if stats.suspicion_score >= 100.0 {
                    stats.is_blocked = true;
                    warn!("🚨 封禁 Client {}：检测到恶意 DDoS 行为！", client_ip);
                    should_block = true;
                } else {
                    // 随着时间推移，降低怀疑值 (冷却)
                    stats.suspicion_score *= 0.8;
                }
                
                // 定期重置统计窗口，避免长期累积
                if duration > 600.0 {
                   stats.total_queries = 0;
                   stats.nxdomain_count = 0;
                   stats.start_time = Instant::now();
                }
            }
        })
        .or_insert(ClientStats {
            total_queries: 1,
            nxdomain_count: if is_nxdomain { 1 } else { 0 },
            start_time: Instant::now(),
            last_query: Instant::now(),
            suspicion_score: 0.0,
            is_blocked: false,
        });
        
    should_block
}




#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_score() {
        let m = UpstreamMetrics::new("test".to_string());
        
        // Initial score should be high
        assert!(m.get_score() >= 500);
        
        // Record some successes
        m.record_success(20);
        m.record_success(25);
        m.record_success(18);
        
        // Score should still be decent
        assert!(m.get_score() > 300);
        
        // Record failures
        m.record_failure();
        m.record_failure();
        m.record_failure();
        
        // Should be marked unhealthy now
        assert!(!m.healthy.load(Ordering::Relaxed));
    }
    
    #[test]
    fn test_autopilot_ranking() {
        let ap = AutoPilot::new();
        
        let m1 = ap.register("fast:53".to_string());
        let m2 = ap.register("slow:53".to_string());
        
        // Fast gets good latency
        m1.record_success(10);
        m1.record_success(12);
        
        // Slow gets bad latency
        m2.record_success(200);
        m2.record_success(250);
        
        // Best should be fast
        let best = ap.get_top_upstream();
        assert_eq!(best, Some("fast:53".to_string()));
    }
}

// ============== Level 15: EDNS Client Subnet (ECS) ==============

/// ECS 配置
#[derive(Debug, Clone)]
pub struct EcsConfig {
    /// 是否启用 ECS
    pub enabled: bool,
    /// 内网客户端使用的公网 IP (用于向上游发送 ECS)
    /// 例如：家庭网关的公网 IP
    pub default_public_ip: Option<std::net::IpAddr>,
    /// IPv4 客户端的源前缀长度 (默认 24，即 /24)
    pub ipv4_prefix_length: u8,
    /// IPv6 客户端的源前缀长度 (默认 56)
    pub ipv6_prefix_length: u8,
}

impl Default for EcsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_public_ip: None,
            ipv4_prefix_length: 24,
            ipv6_prefix_length: 56,
        }
    }
}

/// 全局 ECS 配置
static ECS_CONFIG: Lazy<RwLock<EcsConfig>> = Lazy::new(|| RwLock::new(EcsConfig::default()));

/// 设置 ECS 配置
pub fn set_ecs_config(config: EcsConfig) {
    let enabled = config.enabled;
    let public_ip = config.default_public_ip;
    *ECS_CONFIG.write() = config;
    if enabled {
        info!("⚡ EDNS Client Subnet 已启用 (公网IP: {:?})", public_ip);
    }
}

/// 获取 ECS 配置
pub fn get_ecs_config() -> EcsConfig {
    ECS_CONFIG.read().clone()
}

/// 判断 IP 是否为内网地址
pub fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
        }
        std::net::IpAddr::V6(v6) => {
            // ::1 (loopback)
            v6.is_loopback()
            // fe80::/10 (link-local)
            || v6.segments()[0] & 0xffc0 == 0xfe80
            // fc00::/7 (unique local)
            || v6.segments()[0] & 0xfe00 == 0xfc00
        }
    }
}

/// 构建 ECS 选项字节 (RFC 7871 格式)
/// 返回: Option 数据 (不包含 OPTION-CODE 和 OPTION-LENGTH)
pub fn build_ecs_option(client_ip: std::net::IpAddr, source_prefix_len: u8) -> Vec<u8> {
    let mut data = Vec::new();
    
    match client_ip {
        std::net::IpAddr::V4(v4) => {
            // FAMILY: 1 for IPv4
            data.push(0x00);
            data.push(0x01);
            // SOURCE PREFIX-LENGTH
            data.push(source_prefix_len);
            // SCOPE PREFIX-LENGTH (0 in query)
            data.push(0x00);
            // ADDRESS (truncated to prefix length)
            let octets = v4.octets();
            let bytes_needed = ((source_prefix_len + 7) / 8) as usize;
            data.extend_from_slice(&octets[..bytes_needed.min(4)]);
        }
        std::net::IpAddr::V6(v6) => {
            // FAMILY: 2 for IPv6
            data.push(0x00);
            data.push(0x02);
            // SOURCE PREFIX-LENGTH
            data.push(source_prefix_len);
            // SCOPE PREFIX-LENGTH (0 in query)
            data.push(0x00);
            // ADDRESS (truncated to prefix length)
            let octets = v6.octets();
            let bytes_needed = ((source_prefix_len + 7) / 8) as usize;
            data.extend_from_slice(&octets[..bytes_needed.min(16)]);
        }
    }
    
    data
}

/// 获取用于 ECS 的客户端 IP
/// - 如果是内网 IP，使用配置的公网 IP
/// - 如果是公网 IP，直接使用
pub fn get_ecs_client_ip(client_ip: std::net::IpAddr) -> Option<std::net::IpAddr> {
    let config = get_ecs_config();
    
    if !config.enabled {
        return None;
    }
    
    if is_private_ip(client_ip) {
        // 内网客户端，使用配置的公网 IP
        config.default_public_ip
    } else {
        // 公网客户端，直接使用
        Some(client_ip)
    }
}

/// 获取 ECS 源前缀长度
pub fn get_ecs_prefix_length(ip: std::net::IpAddr) -> u8 {
    let config = get_ecs_config();
    match ip {
        std::net::IpAddr::V4(_) => config.ipv4_prefix_length,
        std::net::IpAddr::V6(_) => config.ipv6_prefix_length,
    }
}

// ============== Level 21: 预测性预取 - 基于时间模式预热 ==============

/// 时间模式记录: 记录每小时的域名访问频率
/// key: (domain, hour) -> access_count
static TIME_PATTERN_ACCESS: Lazy<DashMap<(String, u8), u32>> = Lazy::new(DashMap::new);

/// 预取候选队列 (等待预热的域名)
static PREFETCH_QUEUE: Lazy<DashMap<String, Instant>> = Lazy::new(DashMap::new);

/// 最大时间模式记忆
const MAX_TIME_PATTERNS: usize = 50000;

/// 记录带时间的域名访问 (用于学习时间模式)
pub fn record_timed_access(domain: &str) {
    let hour = chrono::Local::now().hour() as u8;
    let key = (domain.to_lowercase(), hour);
    
    TIME_PATTERN_ACCESS.entry(key)
        .and_modify(|count| *count = count.saturating_add(1))
        .or_insert(1);
    
    // 定期清理
    if TIME_PATTERN_ACCESS.len() > MAX_TIME_PATTERNS {
        cleanup_time_patterns();
    }
}

/// 获取指定小时热门域名 (用于预取)
pub fn get_hot_domains_for_hour(hour: u8, limit: usize) -> Vec<(String, u32)> {
    let mut domains: Vec<_> = TIME_PATTERN_ACCESS.iter()
        .filter(|e| e.key().1 == hour)
        .map(|e| (e.key().0.clone(), *e.value()))
        .collect();
    
    // 按访问次数降序排序
    domains.sort_by(|a, b| b.1.cmp(&a.1));
    domains.truncate(limit);
    domains
}

/// 获取下一小时需要预热的域名
pub fn get_prefetch_candidates(limit: usize) -> Vec<String> {
    let next_hour = (chrono::Local::now().hour() as u8 + 1) % 24;
    get_hot_domains_for_hour(next_hour, limit)
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

/// 将域名加入预取队列
pub fn queue_for_prefetch(domain: &str) {
    PREFETCH_QUEUE.insert(domain.to_lowercase(), Instant::now());
}

/// 从预取队列获取待预热域名 (一次性取出)
pub fn drain_prefetch_queue(limit: usize) -> Vec<String> {
    let mut result = Vec::new();
    let now = Instant::now();
    
    // 取出不超过 limit 个，且入队超过 100ms 的
    for entry in PREFETCH_QUEUE.iter() {
        if result.len() >= limit {
            break;
        }
        if now.duration_since(*entry.value()) > Duration::from_millis(100) {
            result.push(entry.key().clone());
        }
    }
    
    // 移除取出的
    for domain in &result {
        PREFETCH_QUEUE.remove(domain);
    }
    
    result
}

/// 清理时间模式数据 (保留最近24小时最热门的)
fn cleanup_time_patterns() {
    // 简单策略: 保留访问次数 > 1 的
    TIME_PATTERN_ACCESS.retain(|_, count| *count > 1);
    
    // 如果还是太多，减半所有计数
    if TIME_PATTERN_ACCESS.len() > MAX_TIME_PATTERNS / 2 {
        for mut entry in TIME_PATTERN_ACCESS.iter_mut() {
            *entry.value_mut() /= 2;
        }
        TIME_PATTERN_ACCESS.retain(|_, count| *count > 0);
    }
    
    debug!("🧹 时间模式清理完成: 剩余 {} 条", TIME_PATTERN_ACCESS.len());
}

/// 获取时间模式统计
pub fn get_time_pattern_stats() -> (usize, u32) {
    let total = TIME_PATTERN_ACCESS.len();
    let max_count = TIME_PATTERN_ACCESS.iter()
        .map(|e| *e.value())
        .max()
        .unwrap_or(0);
    (total, max_count)
}

/// 启动预测性预取后台任务
pub fn start_predictive_prefetch_task<F>(prefetch_fn: F) 
where
    F: Fn(String) + Send + Sync + 'static,
{
    let prefetch_fn = std::sync::Arc::new(prefetch_fn);
    
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 每5分钟
        
        loop {
            interval.tick().await;
            
            // 获取下一小时热门域名
            let candidates = get_prefetch_candidates(50);
            
            if !candidates.is_empty() {
                info!("🔮 预测性预取: 下一小时热门域名 {} 个", candidates.len());
                
                for domain in candidates {
                    (prefetch_fn)(domain);
                    // 避免短时间内大量预取
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });
}

// ============== Level 19: 响应质量评分 - IP 可达性验证 ==============

/// IP 质量缓存
/// key: IP地址 -> (可达性, 延迟ms, 最后检测时间)
static IP_QUALITY_CACHE: Lazy<DashMap<std::net::IpAddr, IpQuality>> = Lazy::new(DashMap::new);

/// 上游质量惩罚 (返回不可达IP的上游)
/// key: upstream_label -> penalty_score (0-100)
static UPSTREAM_QUALITY_PENALTY: Lazy<DashMap<String, u32>> = Lazy::new(DashMap::new);

/// IP 质量记录
#[derive(Debug, Clone)]
pub struct IpQuality {
    /// 是否可达
    pub reachable: bool,
    /// TCP 连接延迟 (ms)
    pub tcp_latency_ms: Option<u64>,
    /// 最后检测时间
    pub last_check: Instant,
    /// 检测次数
    pub check_count: u32,
    /// 失败次数
    pub fail_count: u32,
}

impl IpQuality {
    fn new() -> Self {
        Self {
            reachable: true, // 默认假设可达
            tcp_latency_ms: None,
            last_check: Instant::now(),
            check_count: 0,
            fail_count: 0,
        }
    }
    
    fn record_success(&mut self, latency_ms: u64) {
        self.reachable = true;
        self.tcp_latency_ms = Some(latency_ms);
        self.last_check = Instant::now();
        self.check_count += 1;
    }
    
    fn record_failure(&mut self) {
        self.fail_count += 1;
        self.check_count += 1;
        self.last_check = Instant::now();
        
        // 连续失败3次才标记为不可达
        if self.fail_count >= 3 || (self.check_count >= 3 && self.fail_count * 2 > self.check_count) {
            self.reachable = false;
        }
    }
    
    /// 是否需要重新检测
    fn needs_recheck(&self) -> bool {
        let age = self.last_check.elapsed();
        // 可达的 IP 每 5 分钟重检
        // 不可达的 IP 每 1 分钟重检 (给机会恢复)
        if self.reachable {
            age > Duration::from_secs(300)
        } else {
            age > Duration::from_secs(60)
        }
    }
}

/// 检测 IP 可达性 (TCP 连接测试)
pub async fn check_ip_reachability(ip: std::net::IpAddr, port: u16) -> Option<u64> {
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    
    let addr = std::net::SocketAddr::new(ip, port);
    let start = Instant::now();
    
    // 尝试 TCP 连接，超时 2 秒
    match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            let latency = start.elapsed().as_millis() as u64;
            Some(latency)
        }
        _ => None,
    }
}

/// 记录 IP 质量 (异步后台调用)
pub fn record_ip_quality(ip: std::net::IpAddr, reachable: bool, latency_ms: Option<u64>) {
    IP_QUALITY_CACHE.entry(ip)
        .and_modify(|entry| {
            if reachable {
                entry.record_success(latency_ms.unwrap_or(0));
            } else {
                entry.record_failure();
            }
        })
        .or_insert_with(|| {
            let mut q = IpQuality::new();
            if reachable {
                q.record_success(latency_ms.unwrap_or(0));
            } else {
                q.record_failure();
            }
            q
        });
}

/// 获取 IP 质量 (用于过滤)
pub fn get_ip_quality(ip: std::net::IpAddr) -> Option<IpQuality> {
    IP_QUALITY_CACHE.get(&ip).map(|e| e.clone())
}

/// 检查 IP 是否已知不可达
pub fn is_ip_known_bad(ip: std::net::IpAddr) -> bool {
    if let Some(quality) = IP_QUALITY_CACHE.get(&ip) {
        !quality.reachable && !quality.needs_recheck()
    } else {
        false // 未知 IP 假设可达
    }
}

/// 记录上游返回了不可达 IP
pub fn penalize_upstream_for_bad_ip(upstream: &str, bad_ip_count: u32) {
    UPSTREAM_QUALITY_PENALTY.entry(upstream.to_string())
        .and_modify(|penalty| {
            *penalty = (*penalty + bad_ip_count * 10).min(100);
        })
        .or_insert(bad_ip_count * 10);
    
    debug!("⚠️ 上游 {} 惩罚 +{} (返回不可达IP)", upstream, bad_ip_count * 10);
}

/// 获取上游质量惩罚分
pub fn get_upstream_quality_penalty(upstream: &str) -> u32 {
    UPSTREAM_QUALITY_PENALTY.get(upstream).map(|v| *v).unwrap_or(0)
}

/// 衰减上游惩罚 (定期调用，给机会恢复)
pub fn decay_upstream_penalties() {
    for mut entry in UPSTREAM_QUALITY_PENALTY.iter_mut() {
        if *entry.value() > 0 {
            *entry.value_mut() = entry.value().saturating_sub(5);
        }
    }
    UPSTREAM_QUALITY_PENALTY.retain(|_, v| *v > 0);
}

/// 后台验证 DNS 响应中的 IP (异步调用)
pub fn spawn_ip_verification(ips: Vec<std::net::IpAddr>, upstream: String) {
    // 限制并发验证数量
    if ips.is_empty() || ips.len() > 10 {
        return;
    }
    
    tokio::spawn(async move {
        let mut bad_count = 0u32;
        
        for ip in ips {
            // 跳过已验证过的
            if let Some(quality) = get_ip_quality(ip) {
                if !quality.needs_recheck() {
                    if !quality.reachable {
                        bad_count += 1;
                    }
                    continue;
                }
            }
            
            // 根据 IP 类型选择端口
            let port = if ip.is_ipv4() { 80 } else { 80 }; // HTTP 端口
            
            match check_ip_reachability(ip, port).await {
                Some(latency) => {
                    record_ip_quality(ip, true, Some(latency));
                    debug!("✅ IP 可达: {} ({}ms)", ip, latency);
                }
                None => {
                    record_ip_quality(ip, false, None);
                    bad_count += 1;
                    debug!("❌ IP 不可达: {}", ip);
                }
            }
            
            // 避免短时间内大量连接
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        
        // 惩罚返回不可达 IP 的上游
        if bad_count > 0 {
            penalize_upstream_for_bad_ip(&upstream, bad_count);
        }
    });
}

/// 获取 IP 质量统计
pub fn get_ip_quality_stats() -> (usize, usize, usize) {
    let total = IP_QUALITY_CACHE.len();
    let reachable = IP_QUALITY_CACHE.iter().filter(|e| e.reachable).count();
    let unreachable = total - reachable;
    (total, reachable, unreachable)
}

/// 清理过期 IP 质量记录
pub fn cleanup_ip_quality_cache() {
    let now = Instant::now();
    IP_QUALITY_CACHE.retain(|_, v| {
        now.duration_since(v.last_check) < Duration::from_secs(3600) // 保留 1 小时内的
    });
}

/// 启动 IP 质量验证后台任务 (定期衰减惩罚、清理缓存)
pub fn start_ip_quality_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // 衰减惩罚
            decay_upstream_penalties();
            
            // 清理过期缓存
            cleanup_ip_quality_cache();
            
            let (total, reachable, unreachable) = get_ip_quality_stats();
            if total > 0 {
                debug!("📊 IP质量统计: 总计={}, 可达={}, 不可达={}", total, reachable, unreachable);
            }
        }
    });
}

// ============== Level 22: 国内热门域名预热库 ==============

/// 国内热门 App 域名 (微信/抖音/QQ/淘宝/百度等)
/// 这些域名访问频率极高，应该始终保持缓存热状态
pub const CHINA_HOT_DOMAINS: &[&str] = &[
    // 微信 WeChat
    "weixin.qq.com",
    "wx.qq.com",
    "mp.weixin.qq.com",
    "res.wx.qq.com",
    "szextshort.weixin.qq.com",
    "szlong.weixin.qq.com",
    "szshort.weixin.qq.com",
    
    // QQ
    "qq.com",
    "www.qq.com",
    "im.qq.com",
    "web.qq.com",
    "qzone.qq.com",
    
    // 抖音 TikTok China
    "douyin.com",
    "www.douyin.com",
    "api.douyin.com",
    "lf1-cdn-tos.bytegoofy.com",
    "p3-pc.douyinpic.com",
    "v.douyin.com",
    
    // 头条
    "toutiao.com",
    "www.toutiao.com",
    "lf.snssdk.com",
    
    // 淘宝/天猫/阿里
    "taobao.com",
    "www.taobao.com",
    "tmall.com",
    "www.tmall.com",
    "alipay.com",
    "www.alipay.com",
    "aliyun.com",
    "www.aliyun.com",
    
    // 百度
    "baidu.com",
    "www.baidu.com",
    "tieba.baidu.com",
    "pan.baidu.com",
    "map.baidu.com",
    
    // 京东
    "jd.com",
    "www.jd.com",
    "m.jd.com",
    
    // 美团/大众点评
    "meituan.com",
    "www.meituan.com",
    "dianping.com",
    "www.dianping.com",
    
    // 网易
    "163.com",
    "www.163.com",
    "music.163.com",
    
    // 新浪/微博
    "weibo.com",
    "www.weibo.com",
    "api.weibo.cn",
    
    // 哔哩哔哩
    "bilibili.com",
    "www.bilibili.com",
    "api.bilibili.com",
    "data.bilibili.com",
    
    // 知乎
    "zhihu.com",
    "www.zhihu.com",
    
    // 小红书
    "xiaohongshu.com",
    "www.xiaohongshu.com",
    
    // 拼多多
    "pinduoduo.com",
    "www.pinduoduo.com",
    
    // 爱奇艺/优酷/腾讯视频
    "iqiyi.com",
    "www.iqiyi.com",
    "youku.com",
    "www.youku.com",
    "v.qq.com",
    
    // 滴滴
    "didiglobal.com",
    "xiaojukeji.com",
    
    // 饿了么
    "ele.me",
    "www.ele.me",
    
    // 支付/金融
    "95599.cn", // 农行
    "icbc.com.cn", // 工行
    "ccb.com", // 建行
];

/// 获取热门域名列表
pub fn get_china_hot_domains() -> &'static [&'static str] {
    CHINA_HOT_DOMAINS
}

/// 获取热门域名数量
pub fn get_china_hot_domains_count() -> usize {
    CHINA_HOT_DOMAINS.len()
}

/// 检查域名是否为热门国内域名
pub fn is_china_hot_domain(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    CHINA_HOT_DOMAINS.iter().any(|hot| {
        domain_lower == *hot || domain_lower.ends_with(&format!(".{}", hot))
    })
}

/// 启动热门域名定期预热任务
pub fn start_hot_domain_prefetch_task<F>(prefetch_fn: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let prefetch_fn = std::sync::Arc::new(prefetch_fn);
    
    tokio::spawn(async move {
        // 启动后立即预热一次
        tokio::time::sleep(Duration::from_secs(10)).await;
        info!("🔥 首次热门域名预热开始: {} 个域名", CHINA_HOT_DOMAINS.len());
        
        for domain in CHINA_HOT_DOMAINS {
            (prefetch_fn)(domain);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        info!("🔥 首次热门域名预热完成");
        
        // 之后每 30 分钟预热一次
        let mut interval = tokio::time::interval(Duration::from_secs(1800));
        interval.tick().await; // 跳过第一次 (刚刚预热过)
        
        loop {
            interval.tick().await;
            
            info!("🔥 定期热门域名预热: {} 个域名", CHINA_HOT_DOMAINS.len());
            
            for domain in CHINA_HOT_DOMAINS {
                (prefetch_fn)(domain);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    });
}

/// 获取 AI 智能化统计摘要
pub fn get_ai_intelligence_summary() -> String {
    let (ip_total, ip_reachable, ip_unreachable) = get_ip_quality_stats();
    let (time_patterns, _) = get_time_pattern_stats();
    let hot_domains = get_china_hot_domains_count();
    let bandit_count = UPSTREAM_BANDITS.len();
    
    format!(
        "🧠 TitanDNS AI Intelligence Summary:\n\
         ├─ 热门域名库: {} 个\n\
         ├─ 时间模式学习: {} 条\n\
         ├─ IP质量追踪: {} 个 (可达: {}, 不可达: {})\n\
         ├─ Bandit 上游: {} 个\n\
         └─ 域名记忆: {} 条",
        hot_domains,
        time_patterns,
        ip_total, ip_reachable, ip_unreachable,
        bandit_count,
        DOMAIN_MEMORY.len()
    )
}

// ============== Level 23: Thompson Sampling Bandit 上游选择 ==============

/// 上游 Bandit 状态存储
/// key: upstream_label -> BanditState
static UPSTREAM_BANDITS: Lazy<DashMap<String, BanditState>> = Lazy::new(DashMap::new);

/// Bandit 状态 (Beta 分布参数)
#[derive(Debug, Clone)]
pub struct BanditState {
    /// 虚拟成功次数 (Beta 分布 α 参数)
    alpha: f64,
    /// 虚拟失败次数 (Beta 分布 β 参数)  
    beta: f64,
    /// 累计延迟 (用于计算期望延迟)
    total_latency_ms: f64,
    /// 总查询次数
    total_queries: u64,
    /// 最后更新时间
    last_update: Instant,
}

impl BanditState {
    pub fn new() -> Self {
        Self {
            alpha: 1.0,      // 无信息先验 Beta(1,1) = 均匀分布
            beta: 1.0,
            total_latency_ms: 0.0,
            total_queries: 0,
            last_update: Instant::now(),
        }
    }
    
    /// 采样一个分数 (Thompson Sampling 核心)
    /// 返回值在 0-1 之间，越高越好
    pub fn sample(&self) -> f64 {
        // ✅ 性能优化：重用 rng
        let mut rng = rand::thread_rng();
        self.sample_with_rng(&mut rng)
    }

    /// 使用指定的 Rng 采样（避免重复创建 thread_rng）
    fn sample_with_rng<R: rand::Rng>(&self, rng: &mut R) -> f64 {
        // 使用正确的 Beta 分布采样
        let sample = self.beta_sample_with_rng(self.alpha, self.beta, rng);

        // 结合延迟惩罚
        let avg_latency = if self.total_queries > 0 {
            self.total_latency_ms / self.total_queries as f64
        } else {
            50.0  // 默认 50ms
        };

        // 延迟惩罚：每 10ms 额外延迟扣 0.01 分
        let latency_penalty = (avg_latency - 20.0).max(0.0) * 0.001;

        (sample - latency_penalty).max(0.0)
    }

    /// Beta 分布采样 (正确实现)
    /// 使用关系: If X ~ Gamma(α,1) and Y ~ Gamma(β,1), then X/(X+Y) ~ Beta(α,β)
    fn beta_sample(&self, alpha: f64, beta: f64) -> f64 {
        let mut rng = rand::thread_rng();
        self.beta_sample_with_rng(alpha, beta, &mut rng)
    }

    /// Beta 分布采样（使用指定的 Rng，避免重复创建）
    fn beta_sample_with_rng<R: rand::Rng>(&self, alpha: f64, beta: f64, rng: &mut R) -> f64 {
        // 采样 Gamma(α, 1) 和 Gamma(β, 1)
        let x = self.sample_gamma(alpha, rng);
        let y = self.sample_gamma(beta, rng);

        // ✅ 修复潜在除零风险
        let sum = x + y;
        if sum <= f64::EPSILON {
            // 极端情况：返回均匀分布 (理论上不会发生，但数值上可能)
            return 0.5;
        }

        // Beta 分布
        x / sum
    }

    /// Gamma 分布采样 (Marsaglia and Tsang's method)
    /// 采样 Gamma(k, θ=1)
    fn sample_gamma<R: rand::Rng>(&self, k: f64, rng: &mut R) -> f64 {
        if k < 1.0 {
            // 对于 k < 1，使用变换: Gamma(k,1) = Gamma(k+1,1) * U^(1/k)
            return self.sample_gamma(k + 1.0, rng) * rng.gen::<f64>().powf(1.0 / k);
        }

        // Marsaglia and Tsang's method for k >= 1
        let d = k - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();

        loop {
            let mut x: f64;
            let mut v: f64;
            let mut z: f64;

            loop {
                // 生成标准正态分布
                let u1: f64 = rng.gen();
                let u2: f64 = rng.gen();
                let z_val = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

                x = 1.0 + c * z_val;
                v = x * x * x;
                z = z_val;

                if v > 0.0 {
                    break;
                }
            }

            let u: f64 = rng.gen();
            if u < 1.0 - 0.0331 * (z * z).powi(4) {
                return d * v;
            }

            if u.ln() < 0.5 * z * z + d * (1.0 - v + v.ln()) {
                return d * v;
            }
        }
    }
    
    /// 更新成功
    pub fn update_success(&mut self, latency_ms: u64) {
        self.alpha += 1.0;
        self.total_latency_ms += latency_ms as f64;
        self.total_queries += 1;
        self.last_update = Instant::now();
        
        // 防止参数过大，定期衰减
        if self.alpha + self.beta > 1000.0 {
            self.decay();
        }
    }
    
    /// 更新失败
    pub fn update_failure(&mut self) {
        self.beta += 1.0;
        self.total_queries += 1;
        self.last_update = Instant::now();
        
        if self.alpha + self.beta > 1000.0 {
            self.decay();
        }
    }
    
    /// 衰减参数 (保持 exploration)
    fn decay(&mut self) {
        self.alpha = (self.alpha * 0.5).max(1.0);
        self.beta = (self.beta * 0.5).max(1.0);
        self.total_latency_ms *= 0.5;
    }
    
    /// 获取成功率估计
    pub fn success_rate(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }
    
    /// 获取平均延迟
    pub fn avg_latency(&self) -> f64 {
        if self.total_queries > 0 {
            self.total_latency_ms / self.total_queries as f64
        } else {
            50.0
        }
    }
}

/// 记录 Bandit 成功
pub fn bandit_record_success(upstream: &str, latency_ms: u64) {
    UPSTREAM_BANDITS.entry(upstream.to_string())
        .and_modify(|state| state.update_success(latency_ms))
        .or_insert_with(|| {
            let mut s = BanditState::new();
            s.update_success(latency_ms);
            s
        });
}

/// 记录 Bandit 失败
pub fn bandit_record_failure(upstream: &str) {
    UPSTREAM_BANDITS.entry(upstream.to_string())
        .and_modify(|state| state.update_failure())
        .or_insert_with(|| {
            let mut s = BanditState::new();
            s.update_failure();
            s
        });
}

/// 使用 Bandit 采样选择最佳上游
/// 返回: (upstream_label, sampled_score)
pub fn bandit_select_best(upstreams: &[String]) -> Option<(String, f64)> {
    if upstreams.is_empty() {
        return None;
    }

    let mut rng = rand::thread_rng();
    let mut best_upstream = None;
    let mut best_score = f64::NEG_INFINITY;

    for upstream in upstreams {
        let score = match UPSTREAM_BANDITS.get(upstream) {
            Some(state) => {
                // ✅ 修复并发数据竞争：先 clone，再调用 sample()
                let state_clone = state.value().clone();
                state_clone.sample()
            }
            None => {
                // 未知上游，给予乐观初始分数 (鼓励探索)
                // 使用高质量的随机数生成
                0.8 + rng.gen::<f64>() * 0.2  // [0.8, 1.0]
            }
        };

        if score > best_score {
            best_score = score;
            best_upstream = Some(upstream.clone());
        }
    }

    best_upstream.map(|u| (u, best_score))
}

/// 获取 Bandit 排名 (用于调试/展示)
pub fn bandit_get_rankings() -> Vec<(String, f64, f64, f64)> {
    // 返回: (label, success_rate, avg_latency, sample_score)
    let mut rankings: Vec<_> = UPSTREAM_BANDITS.iter()
        .map(|e| {
            // ✅ 修复并发数据竞争：先 clone
            let state = e.value().clone();
            (
                e.key().clone(),
                state.success_rate(),
                state.avg_latency(),
                state.sample(),
            )
        })
        .collect();

    rankings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    rankings
}

/// 获取 Bandit 统计
pub fn bandit_get_stats() -> (usize, f64) {
    let count = UPSTREAM_BANDITS.len();
    let avg_success_rate = if count > 0 {
        UPSTREAM_BANDITS.iter()
            .map(|e| {
                // ✅ 修复并发数据竞争：先 clone
                let state = e.value().clone();
                state.success_rate()
            })
            .sum::<f64>() / count as f64
    } else {
        0.0
    };
    (count, avg_success_rate)
}

/// 打印 Bandit 状态 (调试)
pub fn bandit_print_status() {
    let rankings = bandit_get_rankings();
    
    info!("🎰 Thompson Sampling Bandit Status:");
    for (i, (label, success_rate, avg_latency, score)) in rankings.iter().enumerate() {
        info!("  {}. {} - 成功率: {:.1}%, 延迟: {:.0}ms, 采样分: {:.3}", 
              i + 1, label, success_rate * 100.0, avg_latency, score);
    }
}

// ============== Level 24: Contextual Bandit - 上下文感知选择 ==============

/// 域名类别 (用于 Contextual Bandit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainCategory {
    /// 国内热门 (微信/抖音等)
    ChinaHot,
    /// 国内普通
    ChinaNormal,
    /// 国外
    Foreign,
    /// 未知
    Unknown,
}

/// 每类别的 Bandit 状态
static CATEGORY_BANDITS: Lazy<DashMap<(DomainCategory, String), BanditState>> = Lazy::new(DashMap::new);

/// 自适应探索率 (随时间降低)
static EXPLORATION_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 获取域名类别
pub fn get_domain_category(domain: &str) -> DomainCategory {
    // 检查是否热门国内域名
    if is_china_hot_domain(domain) {
        return DomainCategory::ChinaHot;
    }

    // 检查是否国内普通域名 (简单规则: .cn, .com.cn 等)
    let domain_lower = domain.to_lowercase();

    // 常见国内 TLD
    if domain_lower.ends_with(".cn")
        || domain_lower.ends_with(".com.cn")
        || domain_lower.ends_with(".net.cn")
        || domain_lower.ends_with(".org.cn")
        || domain_lower.ends_with(".gov.cn")
        || domain_lower.ends_with(".edu.cn") {
        return DomainCategory::ChinaNormal;
    }

    // 常见国内域名
    let china_domains = [
        "baidu.com", "qq.com", "taobao.com", "tmall.com", "jd.com",
        "163.com", "sohu.com", "sina.com", "youku.com", "bilibili.com",
        "weibo.com", "zhihu.com", "douban.com", "csdn.net", "jianshu.com",
    ];
    for cd in china_domains {
        if domain_lower.ends_with(cd) {
            return DomainCategory::ChinaNormal;
        }
    }

    // 常见国外 TLD（明显不是中国的）
    let foreign_tlds = [
        ".com", ".org", ".net", ".io", ".co", ".ai", ".gg",
        ".us", ".uk", ".de", ".fr", ".jp", ".kr", ".sg",
        ".gov", ".edu", ".mil",
    ];

    for tld in foreign_tlds {
        if domain_lower.ends_with(tld) {
            // 但需要排除一些特殊情况（如 .com.cn 已经在上面处理了）
            return DomainCategory::Foreign;
        }
    }

    // 其他情况归类为 Unknown
    DomainCategory::Unknown
}

/// 记录带上下文的成功
pub fn contextual_bandit_record_success(domain: &str, upstream: &str, latency_ms: u64) {
    let category = get_domain_category(domain);
    let key = (category, upstream.to_string());
    
    CATEGORY_BANDITS.entry(key)
        .and_modify(|state| state.update_success(latency_ms))
        .or_insert_with(|| {
            let mut s = BanditState::new();
            s.update_success(latency_ms);
            s
        });
    
    // 同时更新全局 Bandit
    bandit_record_success(upstream, latency_ms);
}

/// 记录带上下文的失败
pub fn contextual_bandit_record_failure(domain: &str, upstream: &str) {
    let category = get_domain_category(domain);
    let key = (category, upstream.to_string());
    
    CATEGORY_BANDITS.entry(key)
        .and_modify(|state| state.update_failure())
        .or_insert_with(|| {
            let mut s = BanditState::new();
            s.update_failure();
            s
        });
    
    // 同时更新全局 Bandit
    bandit_record_failure(upstream);
}

/// 上下文感知的上游选择
pub fn contextual_bandit_select(domain: &str, upstreams: &[String]) -> Option<String> {
    if upstreams.is_empty() {
        return None;
    }

    let category = get_domain_category(domain);

    // 自适应探索率: 平滑指数衰减（与全局保持一致）
    let explore_count = EXPLORATION_COUNT.fetch_add(1, Ordering::Relaxed);
    // 探索率从 30% 平滑衰减到 5%
    let exploration_rate = 0.30 * (-(explore_count as f64) / 10000.0).exp().max(0.05);

    // 使用高质量随机数决定是否探索
    let mut rng = rand::thread_rng();
    let explore = rng.gen_bool(exploration_rate);

    let mut best_upstream = None;
    let mut best_score = f64::NEG_INFINITY;

    for upstream in upstreams {
        let key = (category, upstream.clone());

        let score = if explore {
            // 探索模式: 纯 Bandit 采样
            CATEGORY_BANDITS.get(&key)
                .map(|s| {
                    // ✅ 修复并发数据竞争：先 clone
                    let state = s.value().clone();
                    state.sample()
                })
                .unwrap_or(0.9) // 未知给高分鼓励探索
        } else {
            // 利用模式: 使用期望值
            CATEGORY_BANDITS.get(&key)
                .map(|s| {
                    // ✅ 修复并发数据竞争：先 clone
                    let state = s.value().clone();
                    state.success_rate() - state.avg_latency() * 0.001
                })
                .unwrap_or(0.5)
        };

        if score > best_score {
            best_score = score;
            best_upstream = Some(upstream.clone());
        }
    }

    if explore {
        debug!("🎲 Contextual Bandit 探索: {:?} → {:?} (探索率: {:.1}%)",
               category, best_upstream, exploration_rate * 100.0);
    }

    best_upstream
}

/// 获取类别 Bandit 统计
pub fn get_contextual_bandit_stats() -> Vec<(DomainCategory, String, f64, f64)> {
    CATEGORY_BANDITS.iter()
        .map(|e| {
            // ✅ 修复并发数据竞争：先 clone
            let state = e.value().clone();
            let (category, upstream) = e.key().clone();
            (category, upstream, state.success_rate(), state.avg_latency())
        })
        .collect()
}
