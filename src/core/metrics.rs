use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, 
    Counter, CounterVec, HistogramVec, TextEncoder, Encoder
};
use once_cell::sync::Lazy;
use std::cell::Cell;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Sampling (fast, low-overhead) ---

const SAMPLE_BPS_MAX: u32 = 10_000; // 100.00%
const DEFAULT_SAMPLE_BPS: u32 = 1_000; // 10%

const LOCAL_FLUSH_EVERY: u64 = 256;       // batch size before flushing to Prometheus
const LOCAL_FLUSH_INTERVAL_MS: u64 = 1000; // periodic flush ceiling
const LOCAL_TIME_CHECK_MASK: u32 = 0x3F;   // check time every 64 ops

static METRICS_SAMPLE_BPS: Lazy<u32> = Lazy::new(|| {
    // Priority: BPS -> PCT -> default
    if let Ok(v) = env::var("TITANDNS_METRICS_SAMPLE_BPS") {
        if let Ok(mut bps) = v.trim().parse::<u32>() {
            if bps > SAMPLE_BPS_MAX { bps = SAMPLE_BPS_MAX; }
            return bps;
        }
    }

    if let Ok(v) = env::var("TITANDNS_METRICS_SAMPLE_PCT") {
        if let Ok(mut pct) = v.trim().parse::<u32>() {
            if pct > 100 { pct = 100; }
            return pct * 100;
        }
    }

    DEFAULT_SAMPLE_BPS
});

thread_local! {
    static FAST_RNG: Cell<u64> = Cell::new(seed_fast_rng());
    static LOCAL_AGG: LocalAgg = LocalAgg::new();
}

#[inline]
fn seed_fast_rng() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ 0x9e37_79b9_7f4a_7c15u64
}

#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct LocalAgg {
    last_flush_ms: Cell<u64>,
    tick: Cell<u32>,
    query_udp: Cell<u64>,
    query_tcp: Cell<u64>,
    query_dot: Cell<u64>,
    query_doh: Cell<u64>,
    query_doq: Cell<u64>,
    cache_hit: Cell<u64>,
    cache_miss: Cell<u64>,
}

impl LocalAgg {
    fn new() -> Self {
        Self {
            last_flush_ms: Cell::new(now_ms()),
            tick: Cell::new(0),
            query_udp: Cell::new(0),
            query_tcp: Cell::new(0),
            query_dot: Cell::new(0),
            query_doh: Cell::new(0),
            query_doq: Cell::new(0),
            cache_hit: Cell::new(0),
            cache_miss: Cell::new(0),
        }
    }

    #[inline]
    fn inc_query(&self, protocol: &str) {
        match protocol {
            "udp" => self.query_udp.set(self.query_udp.get() + 1),
            "tcp" => self.query_tcp.set(self.query_tcp.get() + 1),
            "dot" => self.query_dot.set(self.query_dot.get() + 1),
            "doh" => self.query_doh.set(self.query_doh.get() + 1),
            "doq" => self.query_doq.set(self.query_doq.get() + 1),
            _ => {
                // Fallback: unknown protocol, flush directly to Prometheus
                QUERY_TOTAL.with_label_values(&[protocol]).inc();
                return;
            }
        }
        self.maybe_flush();
    }

    #[inline]
    fn inc_cache_hit(&self) {
        self.cache_hit.set(self.cache_hit.get() + 1);
        self.maybe_flush();
    }

    #[inline]
    fn inc_cache_miss(&self) {
        self.cache_miss.set(self.cache_miss.get() + 1);
        self.maybe_flush();
    }

    #[inline]
    fn pending(&self) -> u64 {
        self.query_udp.get()
            + self.query_tcp.get()
            + self.query_dot.get()
            + self.query_doh.get()
            + self.query_doq.get()
            + self.cache_hit.get()
            + self.cache_miss.get()
    }

    #[inline]
    fn maybe_flush(&self) {
        let pending = self.pending();
        if pending >= LOCAL_FLUSH_EVERY {
            self.flush(now_ms());
            return;
        }

        let t = self.tick.get().wrapping_add(1);
        self.tick.set(t);
        if (t & LOCAL_TIME_CHECK_MASK) == 0 {
            let now = now_ms();
            if now.saturating_sub(self.last_flush_ms.get()) >= LOCAL_FLUSH_INTERVAL_MS {
                self.flush(now);
            }
        }
    }

    fn flush(&self, now: u64) {
        let q_udp = self.query_udp.get();
        if q_udp > 0 {
            QUERY_TOTAL.with_label_values(&["udp"]).inc_by(q_udp as f64);
            self.query_udp.set(0);
        }
        let q_tcp = self.query_tcp.get();
        if q_tcp > 0 {
            QUERY_TOTAL.with_label_values(&["tcp"]).inc_by(q_tcp as f64);
            self.query_tcp.set(0);
        }
        let q_dot = self.query_dot.get();
        if q_dot > 0 {
            QUERY_TOTAL.with_label_values(&["dot"]).inc_by(q_dot as f64);
            self.query_dot.set(0);
        }
        let q_doh = self.query_doh.get();
        if q_doh > 0 {
            QUERY_TOTAL.with_label_values(&["doh"]).inc_by(q_doh as f64);
            self.query_doh.set(0);
        }
        let q_doq = self.query_doq.get();
        if q_doq > 0 {
            QUERY_TOTAL.with_label_values(&["doq"]).inc_by(q_doq as f64);
            self.query_doq.set(0);
        }

        let hits = self.cache_hit.get();
        if hits > 0 {
            CACHE_HITS.inc_by(hits as f64);
            self.cache_hit.set(0);
        }

        let misses = self.cache_miss.get();
        if misses > 0 {
            CACHE_MISSES.inc_by(misses as f64);
            self.cache_miss.set(0);
        }

        self.last_flush_ms.set(now);
    }
}

#[inline]
fn next_u32() -> u32 {
    FAST_RNG.with(|s| {
        let mut x = s.get();
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        s.set(x);
        (x >> 32) as u32
    })
}

#[inline]
fn should_sample() -> bool {
    let bps = *METRICS_SAMPLE_BPS;
    if bps >= SAMPLE_BPS_MAX { return true; }
    if bps == 0 { return false; }
    (next_u32() % SAMPLE_BPS_MAX) < bps
}

#[inline]
pub fn metrics_sample_bps() -> u32 {
    *METRICS_SAMPLE_BPS
}

// --- Global Metrics Definitions ---

// Total queries received
pub static QUERY_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "titandns_query_total",
        "Total number of DNS queries received",
        &["protocol"] // udp, tcp, etc.
    ).unwrap()
});

// Cache Stats
pub static CACHE_HITS: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "titandns_cache_hits_total",
        "Total number of cache hits"
    ).unwrap()
});

pub static CACHE_MISSES: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "titandns_cache_misses_total",
        "Total number of cache misses"
    ).unwrap()
});

// Upstream Stats
pub static UPSTREAM_REQUESTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "titandns_upstream_requests_total",
        "Total requests sent to upstreams",
        &["upstream"] // e.g., "upstream_remote"
    ).unwrap()
});

pub static UPSTREAM_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "titandns_upstream_errors_total",
        "Total failed upstream requests",
        &["upstream", "reason"]
    ).unwrap()
});

pub static UPSTREAM_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "titandns_upstream_latency_seconds",
        "Upstream response latency in seconds",
        &["upstream"]
    ).unwrap()
});

// Rule Matching Stats
pub static RULE_MATCHED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "titandns_rule_matched_total",
        "Total queries matched by rule plugins",
        &["plugin", "tag"] // e.g. geosite_cn, ip_cn
    ).unwrap()
});

// --- Sampling-aware wrappers ---

#[inline]
pub fn inc_query(protocol: &str) {
    if should_sample() {
        LOCAL_AGG.with(|agg| agg.inc_query(protocol));
    }
}

#[inline]
pub fn inc_cache_hit() {
    if should_sample() {
        LOCAL_AGG.with(|agg| agg.inc_cache_hit());
    }
}

#[inline]
pub fn inc_cache_miss() {
    if should_sample() {
        LOCAL_AGG.with(|agg| agg.inc_cache_miss());
    }
}

#[inline]
pub fn inc_upstream_request(upstream: &str) {
    if should_sample() {
        UPSTREAM_REQUESTS.with_label_values(&[upstream]).inc();
    }
}

#[inline]
pub fn inc_upstream_error(upstream: &str, reason: &str) {
    if should_sample() {
        UPSTREAM_ERRORS.with_label_values(&[upstream, reason]).inc();
    }
}

#[inline]
pub fn observe_upstream_latency(upstream: &str, seconds: f64) {
    if should_sample() {
        UPSTREAM_LATENCY.with_label_values(&[upstream]).observe(seconds);
    }
}

#[inline]
pub fn inc_rule_matched(plugin: &str, tag: &str) {
    if should_sample() {
        RULE_MATCHED.with_label_values(&[plugin, tag]).inc();
    }
}

// --- HTTP Handler ---

pub async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => {},
        Err(e) => {
            return format!("# Error encoding metrics: {}\n", e);
        }
    }

    match String::from_utf8(buffer) {
        Ok(s) => s,
        Err(e) => {
            format!("# Error converting metrics to UTF-8: {}\n", e)
        }
    }
}
