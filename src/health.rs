// TitanDNS Upstream Health Check Module
// Periodically probes upstream servers and marks unhealthy ones

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use futures::stream::{self, StreamExt};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use hickory_proto::op::Message;

/// Health status for a single upstream
#[derive(Debug)]
pub struct UpstreamHealth {
    pub label: String,
    pub is_healthy: AtomicBool,
    pub consecutive_failures: AtomicU64,
    pub last_check: RwLock<Instant>,
    pub avg_latency_ms: AtomicU64,
}

impl UpstreamHealth {
    pub fn new(label: String) -> Self {
        Self {
            label,
            is_healthy: AtomicBool::new(true),
            consecutive_failures: AtomicU64::new(0),
            last_check: RwLock::new(Instant::now()),
            avg_latency_ms: AtomicU64::new(0),
        }
    }

    pub fn mark_success(&self, latency_ms: u64) {
        self.is_healthy.store(true, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        
        // Exponential moving average for latency
        let old = self.avg_latency_ms.load(Ordering::Relaxed);
        let new = if old == 0 { latency_ms } else { (old * 7 + latency_ms * 3) / 10 };
        self.avg_latency_ms.store(new, Ordering::Relaxed);
    }

    pub fn mark_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        
        // Mark unhealthy after 3 consecutive failures
        if failures >= 2 {
            if self.is_healthy.swap(false, Ordering::Relaxed) {
                warn!("⚠️ Upstream '{}' marked UNHEALTHY after {} failures", self.label, failures + 1);
            }
        }
    }

    pub fn is_available(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed)
    }
}

/// Health checker that runs periodic probes
pub struct HealthChecker {
    upstreams: Vec<Arc<UpstreamHealth>>,
    check_interval: Duration,
    probe_timeout: Duration,
}

impl HealthChecker {
    pub fn new(labels: Vec<String>) -> Self {
        let upstreams = labels.into_iter()
            .map(|l| Arc::new(UpstreamHealth::new(l)))
            .collect();
        
        Self {
            upstreams,
            check_interval: Duration::from_secs(30),  // Check every 30s
            probe_timeout: Duration::from_secs(5),
        }
    }

    /// Get health status for an upstream by label
    pub fn get_health(&self, label: &str) -> Option<Arc<UpstreamHealth>> {
        self.upstreams.iter()
            .find(|u| u.label == label)
            .cloned()
    }

    /// Get all healthy upstreams
    pub fn healthy_upstreams(&self) -> Vec<&str> {
        self.upstreams.iter()
            .filter(|u| u.is_available())
            .map(|u| u.label.as_str())
            .collect()
    }

    /// Run the health check loop (spawn this in background)
    pub async fn run_check_loop(&self, shutdown: tokio_util::sync::CancellationToken) {
        info!("🏥 Health Checker started (interval: {:?})", self.check_interval);
        
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("🏥 Health Checker stopping...");
                    break;
                }
                _ = tokio::time::sleep(self.check_interval) => {
                    self.run_health_checks().await;
                }
            }
        }
    }

    async fn run_health_checks(&self) {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        // Build a simple health check query
        let mut msg = Message::new();
        msg.set_id(0xDEAD);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);

        if let Ok(name) = Name::from_ascii("health.check.local") {
            let query = Query::query(name, RecordType::A);
            msg.add_query(query);
        }

        let msg = Arc::new(msg);
        let probe_timeout = self.probe_timeout;
        let max_concurrency = std::cmp::max(1, std::cmp::min(self.upstreams.len(), 32));
        let this = self;

        stream::iter(self.upstreams.iter().cloned())
            .for_each_concurrent(max_concurrency, |upstream| {
                let msg = Arc::clone(&msg);
                async move {
                    let start = Instant::now();

                    // Simple UDP probe (we don't actually need a response)
                    let result = tokio::time::timeout(
                        probe_timeout,
                        this.probe_upstream(&upstream.label, msg.as_ref())
                    )
                    .await;

                    *upstream.last_check.write().await = Instant::now();

                    match result {
                        Ok(Ok(())) => {
                            let latency = start.elapsed().as_millis() as u64;
                            upstream.mark_success(latency);
                            debug!("✅ Health check passed: {} ({}ms)", upstream.label, latency);
                        }
                        Ok(Err(e)) => {
                            upstream.mark_failure();
                            debug!("❌ Health check failed: {} - {}", upstream.label, e);
                        }
                        Err(_) => {
                            upstream.mark_failure();
                            debug!("❌ Health check timeout: {}", upstream.label);
                        }
                    }
                }
            })
            .await;
    }
    async fn probe_upstream(&self, label: &str, _msg: &Message) -> anyhow::Result<()> {
        // Simple socket connectivity check
        // For real implementation, send the DNS probe
        
        // Parse address from label (format: "udp://1.2.3.4:53")
        let addr_str = label
            .trim_start_matches("udp://")
            .trim_start_matches("tcp://")
            .trim_start_matches("tls://")
            .trim_start_matches("https://");
        
        // Just check if we can parse it as an address
        if addr_str.contains('/') {
            // DoH URL - skip for now
            return Ok(());
        }

        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            // Quick TCP connect test (more reliable than UDP)
            let _stream = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(addr)
            ).await??;
            
            Ok(())
        } else {
            // Can't parse, assume healthy
            Ok(())
        }
    }
}

/// Shared health registry (singleton pattern)
use once_cell::sync::OnceCell;
static HEALTH_REGISTRY: OnceCell<Arc<HealthChecker>> = OnceCell::new();

pub fn init_health_checker(labels: Vec<String>) -> Arc<HealthChecker> {
    HEALTH_REGISTRY.get_or_init(|| {
        Arc::new(HealthChecker::new(labels))
    }).clone()
}

pub fn get_health_checker() -> Option<Arc<HealthChecker>> {
    HEALTH_REGISTRY.get().cloned()
}
