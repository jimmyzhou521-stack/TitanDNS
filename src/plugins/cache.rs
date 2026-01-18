use anyhow::Result;
use std::time::Duration;
use std::sync::Arc;
use moka::future::Cache;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinEncoder, BinEncodable};
use tracing::{debug, info, warn};
use dashmap::DashMap;  // For Shadow Refresh reverse mapping
use once_cell::sync::OnceCell;

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::core::simd_hash::SimdDomainHasher;
#[cfg(target_os = "linux")]
use crate::core::task_manager::TaskManager;
use crate::plugins::forward::ForwardPlugin; // Needed for prefetch
use crate::config::UpstreamConfig;
use crate::plugins::AnyPlugin;
use crate::core::metrics;
use crate::plugins::recursive_backend::RecursiveBackend;
use crate::stats::STATS;

use ipnet::IpNet;

// Global XDP Hash Map: qhash -> (domain, qtype, qclass)
// Shared across all CachePlugin instances to avoid duplicate syncs
static GLOBAL_XDP_HASH_MAP: OnceCell<moka::sync::Cache<u64, (String, u16, u16)>> = OnceCell::new();

fn get_global_xdp_hash_map(ttl_secs: u64) -> moka::sync::Cache<u64, (String, u16, u16)> {
    GLOBAL_XDP_HASH_MAP
        .get_or_init(|| {
            moka::sync::Cache::builder()
                .max_capacity(500_000)
                .time_to_live(std::time::Duration::from_secs(ttl_secs))
                .build()
        })
        .clone()
}

// Composite Key for Cache Lookup (optimized with u64 hash and ECS awareness)
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct QueryKey {
    pub name_hash: u64,
    pub qtype: u16,
    pub qclass: u16,
    pub subnet: Option<IpNet>, // Support for ECS-aware caching
}

/// Snapshot of a cache entry for background inspection/refresh.
#[derive(Clone, Debug)]
pub struct CacheEntrySnapshot {
    pub key: QueryKey,
    pub message: Arc<Message>,
    pub timestamp: u64,
    pub ttl: u64,
}

impl QueryKey {
    fn to_bytes(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..8].copy_from_slice(&self.name_hash.to_le_bytes());
        buf[8..10].copy_from_slice(&self.qtype.to_le_bytes());
        buf[10..12].copy_from_slice(&self.qclass.to_le_bytes());
        
        // Serialize subnet (simplified: just first 8 bytes if exists)
        if let Some(net) = self.subnet {
            let addr_bytes = match net.addr() {
                std::net::IpAddr::V4(a) => {
                    let mut b = [0u8; 8];
                    b[0..4].copy_from_slice(&a.octets());
                    b[4] = net.prefix_len();
                    b
                },
                std::net::IpAddr::V6(a) => {
                    let mut b = [0u8; 8];
                    b[0..7].copy_from_slice(&a.octets()[0..7]); // High 56 bits
                    b[7] = net.prefix_len();
                    b
                }
            };
            buf[12..20].copy_from_slice(&addr_bytes);
        }
        buf
    }

    fn from_bytes(bytes: [u8; 20]) -> Self {
        // Safely convert slices to arrays with proper error handling
        let name_hash = if bytes.len() >= 8 {
            u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_else(|_| [0u8; 8]))
        } else {
            0
        };

        let qtype = if bytes.len() >= 10 {
            u16::from_le_bytes(bytes[8..10].try_into().unwrap_or_else(|_| [0u8; 2]))
        } else {
            0
        };

        let qclass = if bytes.len() >= 12 {
            u16::from_le_bytes(bytes[10..12].try_into().unwrap_or_else(|_| [0u8; 2]))
        } else {
            0
        };

        // Note: For simplicity, persistence reconstruction is best-effort.
        Self {
            name_hash,
            qtype,
            qclass,
            subnet: None, // Hard to reconstruct IpNet perfectly from mini-hash, usually ephemeral
        }
    }
}

const DEFAULT_MOKA_TTL_SECS: u64 = 86400 * 7;
const DEFAULT_XDP_HASH_TTL_SECS: u64 = 7200;
const DEFAULT_PREFETCH_CONCURRENT: usize = 2;
const DEFAULT_PREFETCH_TIMEOUT_MS: u64 = 2000;
const DEFAULT_MIN_TTL: u64 = 0;
const DEFAULT_MAX_TTL: u64 = 86400;

#[derive(Debug, Clone)]
pub struct CacheTuning {
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub moka_ttl_secs: u64,
    pub xdp_hash_ttl_secs: u64,
    pub prefetch_concurrent: usize,
    pub prefetch_timeout_ms: u64,
}

impl Default for CacheTuning {
    fn default() -> Self {
        Self {
            min_ttl: DEFAULT_MIN_TTL,
            max_ttl: DEFAULT_MAX_TTL,
            moka_ttl_secs: DEFAULT_MOKA_TTL_SECS,
            xdp_hash_ttl_secs: DEFAULT_XDP_HASH_TTL_SECS,
            prefetch_concurrent: DEFAULT_PREFETCH_CONCURRENT,
            prefetch_timeout_ms: DEFAULT_PREFETCH_TIMEOUT_MS,
        }
    }
}

// CachePlugin - Custom Debug implementation to skip non-Debug fields
pub struct CachePlugin {
    pub name: String,
    // Shared cache instance (Moka is thread-safe)
    cache: Cache<QueryKey, CachedEntry>,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub fakeip_protection: bool,

    // --- Smart Prefetch ---
    prefetch_forwarder: Option<Arc<ForwardPlugin>>,
    prefetch_recursive: Option<Arc<RecursiveBackend>>,
    prefetch_threshold: u64,
    serve_stale_ttl: u64,

    // --- Disk Persistence ---
    persist_file: Option<String>,
    persist_interval: u64,

    // --- Cache Warmup (可选功能) ---
    cache_warmer: Option<Arc<crate::plugins::cache_warmup::CacheWarmer>>,

    // --- XDP Cache (Kernel-level acceleration) ---
    #[cfg(target_os = "linux")]
    xdp_filter: Option<Arc<tokio::sync::Mutex<crate::bpf::DnsBpfFilter>>>,
    xdp_cache_enabled: bool,
    xdp_hash_map: moka::sync::Cache<u64, (String, u16, u16)>,
    #[cfg(target_os = "linux")]
    xdp_refresh_task_mgr: Option<Arc<TaskManager>>,
}

impl std::fmt::Debug for CachePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachePlugin")
            .field("name", &self.name)
            .field("min_ttl", &self.min_ttl)
            .field("max_ttl", &self.max_ttl)
            .field("xdp_cache_enabled", &self.xdp_cache_enabled)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CachePlugin {
    fn drop(&mut self) {
        if let Some(mgr) = self.xdp_refresh_task_mgr.take() {
            mgr.stop();
        }
    }
}

// 缓存条目（使用 Unix 时间戳以便持久化）
// [ZERO-COPY] 增加 raw_bytes 字段存储序列化后的响应
#[derive(Clone, Debug)]
struct CachedEntry {
    message: Arc<Message>,
    raw_bytes: Option<bytes::Bytes>,  // [NEW] Pre-serialized response for zero-copy
    timestamp: u64, // Unix timestamp in seconds
    ttl: u64,       // Original TTL (seconds)
}

impl CachedEntry {
    fn new(message: Message, ttl: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // [ZERO-COPY] Pre-serialize the message for fast cache hits
        let raw_bytes = message.to_vec().ok().map(bytes::Bytes::from);
        let message = Arc::new(message);
        
        Self {
            message,
            raw_bytes,
            timestamp: now,
            ttl,
        }
    }

    fn new_with_bytes(message: Message, ttl: u64, raw_bytes: bytes::Bytes) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            message: Arc::new(message),
            raw_bytes: Some(raw_bytes),
            timestamp: now,
            ttl,
        }
    }

    // Convert to binary for persistence
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let owned;
        let msg_bytes: &[u8] = if let Some(ref raw) = self.raw_bytes {
            raw.as_ref()
        } else {
            owned = self.message.as_ref().to_vec()?;
            owned.as_ref()
        };
        let mut buf = Vec::with_capacity(8 + 8 + 4 + msg_bytes.len());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.ttl.to_le_bytes());
        buf.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
        buf.extend(msg_bytes);
        Ok(buf)
    }

    // Load from binary
    fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 20 {
            return Err(anyhow::anyhow!("Entry too short"));
        }
        let timestamp = u64::from_le_bytes(bytes[0..8].try_into()?);
        let ttl = u64::from_le_bytes(bytes[8..16].try_into()?);
        let len = u32::from_le_bytes(bytes[16..20].try_into()?) as usize;
        
        if bytes.len() < 20 + len {
            return Err(anyhow::anyhow!("Buffer underflow"));
        }
        
        // [ZERO-COPY] Store the raw bytes for fast cache hits
        let raw_bytes = Some(bytes::Bytes::copy_from_slice(&bytes[20..20+len]));
        let message = Message::from_vec(&bytes[20..20+len])?;
        let message = Arc::new(message);
        Ok((Self { message, raw_bytes, timestamp, ttl }, 20 + len))
    }
}

impl CachePlugin {
    pub fn new(size: u64,
               prefetch_conf: Option<(Vec<UpstreamConfig>, u32, u32)>,
               recursive_backend: Option<Arc<RecursiveBackend>>,
               persist_file: Option<String>,
               persist_interval: u64,
               tuning: CacheTuning,
               prefetch_strategy: Option<String>,
               prefetch_timeout_ms: Option<u64>) -> Self {
        // Init Moka Cache
        let cache: Cache<QueryKey, CachedEntry> = Cache::builder()
            .max_capacity(size)
            .time_to_live(Duration::from_secs(tuning.moka_ttl_secs))
            .build();

        let xdp_hash_map = get_global_xdp_hash_map(tuning.xdp_hash_ttl_secs);

        let (mut forwarder, mut threshold, mut stale_ttl) = (None, 0, 0);
        
        if let Some((upstreams, th, st)) = prefetch_conf {
            if !upstreams.is_empty() {
                let effective_timeout_ms = prefetch_timeout_ms.unwrap_or(tuning.prefetch_timeout_ms);
                debug!("⚡ Smart Prefetch ENABLED (Threshold: {}s, Stale: {}s) with {} upstreams", th, st, upstreams.len());
                forwarder = Some(Arc::new(ForwardPlugin::new(
                    "cache_prefetch".to_string(),
                    upstreams,
                    prefetch_strategy.clone(),
                    tuning.prefetch_concurrent,
                    effective_timeout_ms,
                    crate::plugins::forward::ForwardTuning::default(),
                )));
                threshold = th as u64;
                stale_ttl = st as u64;
            }
        }

        let plugin = Self {
            name: "cache".to_string(),
            cache,
            min_ttl: tuning.min_ttl,
            max_ttl: tuning.max_ttl,
            fakeip_protection: false,  // 默认关闭
            prefetch_forwarder: forwarder,
            prefetch_recursive: recursive_backend,
            prefetch_threshold: threshold,
            serve_stale_ttl: stale_ttl,
            persist_file: persist_file.clone(),
            persist_interval,
            cache_warmer: None,  // 默认不启用预热
            #[cfg(target_os = "linux")]
            xdp_filter: None,  // Will be set via set_xdp_filter()
            xdp_cache_enabled: false,
            xdp_hash_map,
            #[cfg(target_os = "linux")]
            xdp_refresh_task_mgr: None,
        };

        // Load cache from disk on startup
        if let Some(ref path) = persist_file {
            plugin.load_from_disk(path);
        }

        plugin
    }

    /// Load cache entries from disk file
    fn load_from_disk(&self, path: &str) {
        let path = path.to_string();
        let cache = self.cache.clone();
        let serve_stale_ttl = self.serve_stale_ttl;

        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::spawn_blocking(move || {
                Self::load_from_disk_blocking(cache, serve_stale_ttl, path);
            });
        } else {
            Self::load_from_disk_blocking(cache, serve_stale_ttl, path);
        }
    }

    fn load_from_disk_blocking(
        cache: Cache<QueryKey, CachedEntry>,
        serve_stale_ttl: u64,
        path: String,
    ) {
        use std::fs::File;
        use std::io::{BufReader, Read};
        
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                info!("💾 No cache file found at {} ({}), starting fresh", path, e);
                return;
            }
        };
        
        let mut reader = BufReader::new(file);
        let mut count = 0u64;
        
        // Simple format: [key_bytes (20)] [entry_len (4)] [entry_bytes...]
        loop {
            let mut key_buf = [0u8; 20];
            if reader.read_exact(&mut key_buf).is_err() { break; }
            
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).is_err() { break; }
            let entry_len = u32::from_le_bytes(len_buf) as usize;
            
            let mut entry_buf = vec![0u8; entry_len];
            if reader.read_exact(&mut entry_buf).is_err() { break; }
            
            let key = QueryKey::from_bytes(key_buf);
            if let Ok((entry, _len)) = CachedEntry::from_bytes(&entry_buf) {
                // Only restore if not expired beyond stale threshold
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let elapsed = now.saturating_sub(entry.timestamp);
                if elapsed < entry.ttl + serve_stale_ttl + 3600 { // Extra hour grace
                    // Fix: Force async insert in sync function using block_on
                    futures::executor::block_on(cache.insert(key, entry));
                    count += 1;
                }
            }
        }
        
        info!("💾 Loaded {} cache entries from {}", count, path);
    }

    /// Save cache to disk (called periodically)
    pub fn save_to_disk(&self) {
        let path = match &self.persist_file {
            Some(p) => p,
            None => return,
        };
        
        use std::fs::{File, create_dir_all};
        use std::io::{BufWriter, Write};
        use std::path::Path;
        
        // Ensure directory exists
        if let Some(parent) = Path::new(path).parent() {
            let _ = create_dir_all(parent);
        }
        
        let file = match File::create(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("💾 Failed to create cache file {}: {}", path, e);
                return;
            }
        };
        
        let mut writer = BufWriter::new(file);
        let mut count = 0u64;
        
        for (key, entry) in self.cache.iter() {
            let key_bytes = key.to_bytes();
            if let Ok(entry_bytes) = entry.to_bytes() {
                let len = entry_bytes.len() as u32;
                if writer.write_all(&key_bytes).is_ok()
                    && writer.write_all(&len.to_le_bytes()).is_ok()
                    && writer.write_all(&entry_bytes).is_ok() {
                    count += 1;
                }
            }
        }
        
        let _ = writer.flush();
        debug!("💾 Saved {} cache entries to {}", count, path);
    }

    /// Start background persistence task
    pub fn start_persistence_task(self: Arc<Self>) {
        if self.persist_file.is_none() || self.persist_interval == 0 {
            return;
        }
        
        let interval = self.persist_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                let plugin = self.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    plugin.save_to_disk();
                })
                .await
                {
                    warn!("💾 Cache persistence task failed: {}", e);
                }
            }
        });
    }

    fn get_key(&self, ctx: &Context) -> Option<QueryKey> {
        let query = ctx.request.query()?;
        let name = ctx.qname_ref();
        
        // Track domain access for AutoPilot hot domains / predictive prefetch
        crate::autopilot::track_domain(name);
        
        // Track QPS for traffic monitoring
        crate::autopilot::record_query();
        
        // Use SIMD hash for domain name
        let mut hasher = SimdDomainHasher::new();
        let name_hash = hasher.hash_domain(name);
        
        // Extra: Extract ECS (EDNS Client Subnet) from EDNS extensions
        let subnet = None;

        Some(QueryKey {
            name_hash,
            qtype: query.query_type().into(),
            qclass: query.query_class().into(),
            subnet,
        })
    }

    pub fn purge(&self) {
        info!("🧹 Purging DNS Cache...");
        self.cache.invalidate_all();
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    /// Snapshot cache entries for background analysis/refresh.
    /// NOTE: This clones responses; use a sensible limit to avoid heavy memory spikes.
    pub fn snapshot_entries(&self, limit: usize) -> Vec<CacheEntrySnapshot> {
        let mut out = Vec::new();
        for (key, entry) in self.cache.iter() {
            out.push(CacheEntrySnapshot {
                key: key.as_ref().clone(),
                message: entry.message.clone(),
                timestamp: entry.timestamp,
                ttl: entry.ttl,
            });
            if limit > 0 && out.len() >= limit {
                break;
            }
        }
        out
    }

    fn build_key_for_domain(&self, domain: &str, qtype: u16, qclass: u16) -> QueryKey {
        let mut hasher = SimdDomainHasher::new();
        let name_hash = hasher.hash_domain(domain);
        QueryKey {
            name_hash,
            qtype,
            qclass,
            subnet: None,
        }
    }

    /// Insert a refreshed response into cache (used by SmartRefresh).
    /// Returns TTL if inserted.
    pub async fn insert_response_for_domain(
        &self,
        domain: &str,
        qtype: u16,
        qclass: u16,
        resp: Message,
    ) -> Option<u64> {
        // Validate cache entry size
        const MAX_CACHE_ENTRY_SIZE: usize = 4096;
        let response_bytes = resp.to_vec().unwrap_or_default();
        if response_bytes.len() > MAX_CACHE_ENTRY_SIZE {
            return None;
        }

        let ttl = self.calculate_ttl(&resp);
        if ttl == 0 {
            return None;
        }

        let key = self.build_key_for_domain(domain, qtype, qclass);
        let raw_bytes = bytes::Bytes::from(response_bytes);
        let entry = CachedEntry::new_with_bytes(resp.clone(), ttl, raw_bytes.clone());
        self.cache.insert(key, entry).await;

        // Sync to XDP kernel cache if enabled
        #[cfg(target_os = "linux")]
        {
            use hickory_proto::rr::Name;
            let mut qname_raw = Vec::new();
            if let Ok(name) = Name::from_ascii(domain) {
                let mut encoder = BinEncoder::new(&mut qname_raw);
                if name.emit(&mut encoder).is_ok() {
                    self.sync_to_xdp(&qname_raw, qtype, qclass, domain, raw_bytes.as_ref(), ttl).await;
                }
            }
        }

        Some(ttl)
    }

    
    // --- Persistence ---

    pub async fn dump_to_file(&self, path: &str) -> Result<()> {
        let path = path.to_string();
        let path_log = path.clone();
        let cache = self.cache.clone();
        let count = tokio::task::spawn_blocking(move || -> Result<usize> {
            use std::io::Write;
            let mut file = std::fs::File::create(&path)?;
            let mut count = 0usize;

            for (key, entry) in cache.iter() {
                let key_bytes = key.to_bytes();
                let entry_bytes = entry.to_bytes()?;

                file.write_all(&key_bytes)?;
                file.write_all(&entry_bytes)?;
                count += 1;
            }

            file.sync_all()?;
            Ok(count)
        })
        .await??;

        info!("💾 Cache dumped: {} entries saved to {}", count, path_log);
        Ok(())
    }

    pub async fn load_from_file(&self, path: &str) -> Result<()> {
        let buf = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let mut offset = 0;
        let mut count = 0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        while offset + 20 <= buf.len() {
            let key_data: [u8; 20] = buf[offset..offset+20].try_into()?;
            let key = QueryKey::from_bytes(key_data);
            offset += 20;

            match CachedEntry::from_bytes(&buf[offset..]) {
                Ok((entry, consumed)) => {
                    offset += consumed;
                    // Check if already expired (with some grace period for stale serve)
                    let elapsed = now.saturating_sub(entry.timestamp);
                    if elapsed < entry.ttl + self.serve_stale_ttl {
                        self.cache.insert(key, entry).await;
                        count += 1;
                    }
                }
                Err(e) => {
                    warn!("⚠️ Failed to parse cache entry at offset {}: {}", offset, e);
                    break;
                }
            }
        }

        info!("💾 Cache loaded: {} entries from {}", count, path);
        Ok(())
    }

    // Internal Helper to calculate TTL from response
    fn calculate_ttl(&self, resp: &Message) -> u64 {
         let mut ttl = self.max_ttl;
         for ans in resp.answers() {
             if (ans.ttl() as u64) < ttl {
                 ttl = ans.ttl() as u64;
             }
         }
         if ttl < self.min_ttl { ttl = self.min_ttl; }
         ttl
    }

    /// 启用缓存预热功能（可选，预留接口）
    ///
    /// 注意：当前版本只预留接口，实际预热功能需要在服务启动后手动调用
    pub fn enable_cache_warmup(&mut self, _forwarder: Arc<ForwardPlugin>) {
        // [缓存预热] 预留接口，默认不启用
        info!("🔥 Cache warmup interface enabled for: {} (manual activation required)", self.name);
    }

    /// 启用智能刷新功能（可选，预留接口）
    ///
    /// 注意：当前已有 Shadow Refresh 功能，此接口为将来扩展预留
    pub fn enable_smart_refresh(&mut self, _forwarder: Arc<ForwardPlugin>) {
        // [智能刷新] 预留接口，默认不启用（使用现有的 Shadow Refresh）
        info!("🔄 Smart refresh interface enabled for: {} (using existing Shadow Refresh)", self.name);
    }

    /// Set XDP filter for kernel-level caching
    #[cfg(target_os = "linux")]
    pub fn set_xdp_filter(&mut self, filter: Arc<tokio::sync::Mutex<crate::bpf::DnsBpfFilter>>) {
        self.xdp_filter = Some(filter.clone());
        info!("⚡ XDP Cache filter attached to CachePlugin: {}", self.name);

        // Clone self fields for the background task
        let filter_clone = filter.clone();
        let prefetch_recursive = self.prefetch_recursive.clone();
        let cache_clone = self.cache.clone();
        let xdp_hash_map = self.xdp_hash_map.clone();
        let xdp_enabled = self.xdp_cache_enabled;
        let plugin_name = self.name.clone();
        let plugin_name_task = plugin_name.clone();

        // Stop previous refresh task if any
        if let Some(mgr) = self.xdp_refresh_task_mgr.take() {
            mgr.stop();
        }

        let task_mgr = Arc::new(TaskManager::new());
        self.xdp_refresh_task_mgr = Some(task_mgr.clone());

        // Start Background Task: Stats + Shadow Refresh Polling
        let started = task_mgr.start(move |shutdown| async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1)); // Poll every 1 second
            let mut stats_interval_counter = 0u32;

            // Only sync stats from one plugin instance to avoid duplicate logs
            let should_sync_stats = plugin_name_task.contains("domestic") || plugin_name_task == "cache";

            // Deduplication: Track recently processed qhashes (qhash -> last_processed_epoch)
            let refresh_dedup: std::sync::Arc<DashMap<u64, u64>> = std::sync::Arc::new(DashMap::new());

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        stats_interval_counter += 1;

                        // Try to acquire lock (non-blocking)
                        if let Ok(mut guard) = filter_clone.try_lock() {
                    // Poll Shadow Refresh events from Ring Buffer
                    let dedup = refresh_dedup.clone();
                    let refresh_count = guard.poll_refresh_events(|qhash| {
                        // Deduplication: Skip if processed within last 5 seconds
                        let now_epoch = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        if let Some(last) = dedup.get(&qhash) {
                            if now_epoch < *last + 5 {
                                return; // Skip, already processed recently
                            }
                        }
                        dedup.insert(qhash, now_epoch);

                        // Cleanup old entries (keep map small)
                        if dedup.len() > 1000 {
                            dedup.retain(|_, v| now_epoch < *v + 60);
                        }

                        // Look up domain info from reverse mapping
                        if let Some((domain, qtype, qclass)) = xdp_hash_map.get(&qhash) {
                            debug!("🔄 Shadow Refresh event: {} (type={})", domain, qtype);

                            // Trigger background refresh
                            if let Some(ref recursive) = prefetch_recursive {
                                let recursive_clone = recursive.clone();
                                let cache_for_refresh = cache_clone.clone();
                                let filter_for_refresh = filter_clone.clone();
                                let domain_clone = domain.clone();

                                tokio::spawn(async move {
                                    match recursive_clone.lookup(&domain_clone, qtype).await {
                                        Ok(response) => {
                                            let ttl: u32 = response.answers()
                                                .iter()
                                                .map(|r: &hickory_proto::rr::Record| r.ttl())
                                                .min()
                                                .unwrap_or(300);

                                            let response_bytes = match response.to_vec() {
                                                Ok(b) => b,
                                                Err(e) => {
                                                    warn!(
                                                        "❌ Shadow Refresh encode failed for {}: {}",
                                                        domain_clone, e
                                                    );
                                                    return;
                                                }
                                            };
                                            let raw_bytes = bytes::Bytes::from(response_bytes);

                                            let qname_raw = if let Some(query) = response.queries().first() {
                                                let mut qname_raw = Vec::new();
                                                let mut encoder = BinEncoder::new(&mut qname_raw);
                                                if hickory_proto::serialize::binary::BinEncodable::emit(query.name(), &mut encoder).is_ok() {
                                                    Some(qname_raw)
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };

                                            // Update Moka cache
                                            let mut hasher = SimdDomainHasher::new();
                                            let name_hash = hasher.hash_domain(&domain_clone);
                                            let key = QueryKey {
                                                name_hash,
                                                qtype,
                                                qclass,
                                                subnet: None,
                                            };
                                            let entry = CachedEntry::new_with_bytes(
                                                response,
                                                ttl as u64,
                                                raw_bytes.clone(),
                                            );
                                            cache_for_refresh.insert(key, entry).await;

                                            // Update XDP cache
                                            if xdp_enabled {
                                                if let Some(qname_raw) = qname_raw {
                                                    let mut guard = filter_for_refresh.lock().await;
                                                    if guard
                                                        .update_cache(
                                                            &qname_raw,
                                                            qtype,
                                                            qclass,
                                                            raw_bytes.as_ref(),
                                                            ttl as u64,
                                                        )
                                                        .is_ok()
                                                    {
                                                        debug!(
                                                            "✅ Shadow Refresh updated: {} (TTL: {}s)",
                                                            domain_clone, ttl
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("❌ Shadow Refresh failed for {}: {}", domain_clone, e);
                                        }
                                    }
                                });
                            }
                        }
                    });

                    if refresh_count > 0 {
                        debug!("🔄 Processed {} Shadow Refresh events", refresh_count);
                    }

                    // Update stats every tick (1 second) for real-time frontend
                    // But only log every 3 ticks (3 seconds) to avoid spam
                    // Only sync from one plugin instance to prevent race/duplicate
                    if should_sync_stats {
                        match guard.get_cache_stats() {
                            Ok(s) => {
                                crate::stats::STATS.set_xdp_hits(s.cache_hits);

                                if stats_interval_counter >= 3 {
                                    info!(
                                        "📊 XDP Stats Sync: Hits={}, Misses={}, Shadows={}",
                                        s.cache_hits, s.cache_misses, s.shadow_refreshes
                                    );
                                    stats_interval_counter = 0;
                                }
                            }
                            Err(e) => {
                                if stats_interval_counter >= 3 {
                                    warn!("Failed to get XDP cache stats: {}", e);
                                    stats_interval_counter = 0;
                                }
                            }
                        }
                    } else if stats_interval_counter >= 3 {
                        stats_interval_counter = 0;
                    }
                }
                    }
                }
            }
        });

        if !started {
            warn!("XDP refresh task not started for: {}", plugin_name);
        }

        // Trigger XDP Cache Warmup (Cold Start Optimization)
        // This syncs already-loaded cache entries to the kernel
        if self.xdp_cache_enabled {
            let cache_clone = self.cache.clone();
            let filter_for_warmup = filter.clone();
            let xdp_hash_map = self.xdp_hash_map.clone();

            tokio::spawn(async move {
                Self::warm_xdp_cache_async(cache_clone, filter_for_warmup, xdp_hash_map).await;
            });
        }
    }

    /// Enable XDP cache synchronization
    pub fn enable_xdp_cache(&mut self, enabled: bool) {
        self.xdp_cache_enabled = enabled;
        if enabled {
            info!("⚡ XDP Cache synchronization ENABLED (kernel-level acceleration)");
        }
    }

    /// Get XDP hash map for Shadow Refresh integration


    /// Trigger Shadow Refresh for a specific qhash
    /// This is called when XDP notifies us that a cache entry's TTL is low
    #[cfg(target_os = "linux")]
    pub fn trigger_shadow_refresh(&self, qhash: u64) {
        // Look up domain info from reverse mapping
        if let Some((domain, qtype, qclass)) = self.xdp_hash_map.get(&qhash) {
            info!("🔄 Shadow Refresh triggered for {} (type={})", domain, qtype);
            
            // Trigger background refresh using prefetch mechanism
            if let Some(ref recursive) = self.prefetch_recursive {
                let recursive_clone = recursive.clone();
                let cache_clone = self.cache.clone();
                let xdp_filter = self.xdp_filter.clone();
                let xdp_enabled = self.xdp_cache_enabled;
                let xdp_hash_map = self.xdp_hash_map.clone();
                let domain_clone = domain.clone();
                
                tokio::spawn(async move {
                    // lookup is async, call it directly
                    match recursive_clone.lookup(&domain_clone, qtype).await {
                        Ok(response) => {
                            // Calculate TTL from response
                            let ttl: u32 = response.answers()
                                .iter()
                                .map(|r: &hickory_proto::rr::Record| r.ttl())
                                .min()
                                .unwrap_or(300);
                            
                            let response_bytes = match response.to_vec() {
                                Ok(b) => b,
                                Err(e) => {
                                    warn!("❌ Shadow Refresh encode failed for {}: {}", domain_clone, e);
                                    return;
                                }
                            };
                            let raw_bytes = bytes::Bytes::from(response_bytes);
                            
                            let qname_raw = if let Some(query) = response.queries().first() {
                                let mut qname_raw = Vec::new();
                                let mut encoder = BinEncoder::new(&mut qname_raw);
                                if hickory_proto::serialize::binary::BinEncodable::emit(query.name(), &mut encoder).is_ok() {
                                    Some(qname_raw)
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            
                            // Update Moka cache
                            let mut hasher = SimdDomainHasher::new();
                            let name_hash = hasher.hash_domain(&domain_clone);
                            let key = QueryKey {
                                name_hash,
                                qtype,
                                qclass,
                                subnet: None,
                            };
                            let entry = CachedEntry::new_with_bytes(response, ttl as u64, raw_bytes.clone());
                            cache_clone.insert(key, entry).await;
                            
                            // Update XDP cache
                            if xdp_enabled {
                                if let Some(filter) = xdp_filter {
                                    // Re-encode domain to wire format
                                    if let Some(qname_raw) = qname_raw {
                                        let mut guard = filter.lock().await;
                                        if guard.update_cache(&qname_raw, qtype, qclass, raw_bytes.as_ref(), ttl as u64).is_ok() {
                                            // Update reverse mapping
                                            let new_hash = Self::calculate_xdp_hash(&qname_raw, qtype, qclass);
                                            xdp_hash_map.insert(new_hash, (domain_clone.clone(), qtype, qclass));
                                            debug!("✅ Shadow Refresh updated: {} (TTL: {}s)", domain_clone, ttl);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("❌ Shadow Refresh failed for {}: {}", domain_clone, e);
                        }
                    }
                });
            }
        }
    }

    /// Sync a cache entry to XDP kernel cache
    #[cfg(target_os = "linux")]
    async fn sync_to_xdp(&self, qname_raw: &[u8], qtype: u16, qclass: u16, domain: &str, response_bytes: &[u8], ttl: u64) {
        if !self.xdp_cache_enabled { return; }

        if let Some(ref filter) = self.xdp_filter {
            // Calculate qhash first for deduplication check
            let qhash = Self::calculate_xdp_hash(qname_raw, qtype, qclass);
            
            // Skip if already synced by another cache plugin (deduplication)
            if self.xdp_hash_map.contains_key(&qhash) {
                debug!("🔄 XDP Sync skipped (already exists): h={:x}", qhash);
                return;
            }
            
            let mut guard = filter.lock().await;

            if let Err(e) = guard.update_cache(qname_raw, qtype, qclass, response_bytes, ttl) {
                debug!("XDP cache update failed: {}", e);
            } else {
                // Save reverse mapping for Shadow Refresh
                self.xdp_hash_map.insert(qhash, (domain.to_string(), qtype, qclass));
            }
        }
    }

    /// Calculate XDP cache hash (must match BPF DJB2 implementation)
    #[cfg(target_os = "linux")]
    fn calculate_xdp_hash(qname_raw: &[u8], qtype: u16, qclass: u16) -> u64 {
        const DJB2_INIT: u64 = 5381;
        
        let mut hash = DJB2_INIT;
        
        // DJB2: hash = hash * 33 + byte = (hash << 5) + hash + byte
        fn djb2_byte(hash: u64, byte: u8) -> u64 {
            let b = if byte >= b'A' && byte <= b'Z' { byte + 32 } else { byte };
            hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(b as u64)
        }
        
        // Hash qname_raw (with lowercase)
        for &byte in qname_raw {
            hash = djb2_byte(hash, byte);
        }
        
        // Hash qtype (big endian)
        for &byte in &qtype.to_be_bytes() {
            hash = djb2_byte(hash, byte);
        }
        
        // Hash qclass (big endian)
        for &byte in &qclass.to_be_bytes() {
            hash = djb2_byte(hash, byte);
        }
        
        hash
    }

    /// Warm up XDP cache with already-loaded entries (Cold Start Optimization)
    /// This is called asynchronously after set_xdp_filter() to pre-populate the kernel cache
    #[cfg(target_os = "linux")]
    async fn warm_xdp_cache_async(
        cache: Cache<QueryKey, CachedEntry>,
        filter: Arc<tokio::sync::Mutex<crate::bpf::DnsBpfFilter>>,
        xdp_hash_map: moka::sync::Cache<u64, (String, u16, u16)>,
    ) {
        use hickory_proto::serialize::binary::BinEncoder;
        use hickory_proto::serialize::binary::BinEncodable;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut synced_count = 0u64;
        let mut skipped_count = 0u64;

        info!("🔥 XDP Cache Warmup starting... (syncing loaded cache to kernel)");

        // Iterate over all cached entries
        for (_key, entry) in cache.iter() {
            // Check if entry is still valid
            let elapsed = now.saturating_sub(entry.timestamp);
            let remaining_ttl = entry.ttl.saturating_sub(elapsed);

            if remaining_ttl == 0 {
                skipped_count += 1;
                continue; // Skip expired entries
            }

            // Extract query info from cached message
            let query = match entry.message.queries().first() {
                Some(q) => q,
                None => {
                    skipped_count += 1;
                    continue;
                }
            };

            // Encode QNAME to wire format
            let mut qname_raw = Vec::new();
            let mut encoder = BinEncoder::new(&mut qname_raw);
            if query.name().emit(&mut encoder).is_err() {
                skipped_count += 1;
                continue;
            }

            let qtype: u16 = query.query_type().into();
            let qclass: u16 = query.query_class().into();

            // Serialize response (prefer cached raw bytes)
            let owned;
            let response_bytes: &[u8] = if let Some(ref raw) = entry.raw_bytes {
                raw.as_ref()
            } else {
                match entry.message.as_ref().to_vec() {
                    Ok(b) => {
                        owned = b;
                        owned.as_ref()
                    }
                    Err(_) => {
                        skipped_count += 1;
                        continue;
                    }
                }
            };

            // Update XDP cache (with lock)
            {
                let mut guard = filter.lock().await;
                if let Err(e) = guard.update_cache(&qname_raw, qtype, qclass, response_bytes, remaining_ttl) {
                    debug!("XDP warmup entry failed: {}", e);
                    skipped_count += 1;
                    continue;
                }
                
                // Update reverse mapping for Shadow Refresh
                let qhash = Self::calculate_xdp_hash(&qname_raw, qtype, qclass);
                let domain = query.name().to_string();
                xdp_hash_map.insert(qhash, (domain, qtype, qclass));
            }

            synced_count += 1;

            // Yield to prevent blocking the runtime (every 100 entries)
            if synced_count % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }

        info!("🔥 XDP Cache Warmup complete: {} entries synced, {} skipped", synced_count, skipped_count);
    }
}

impl Plugin for CachePlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let key = match self.get_key(ctx) {
            Some(k) => k,
            None => return Ok(()),
        };

        // 1. Try Lookup
        if let Some(cached_entry) = self.cache.get(&key).await {
            metrics::inc_cache_hit();
            STATS.record_cache_hit();
            
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let elapsed = now.saturating_sub(cached_entry.timestamp);
            let original_ttl = cached_entry.ttl;
            let remaining = original_ttl.saturating_sub(elapsed);
            
            // Logic:
            // 1. If remaining > 0: Fresh.
            // 2. If remaining == 0: Expired.
            //    Check Serve Stale: elapsed < (original_ttl + serve_stale_ttl)
            
            let is_stale = remaining == 0;
            let can_serve_stale = is_stale && (elapsed < (original_ttl + self.serve_stale_ttl));
            
            // Should usually serve if Fresh OR (Stale && Allowed)
            // But check FakeIP protection first
            if self.fakeip_protection && is_stale {
                 debug!("⚠️ Cache entry EXPIRED (FakeIP protection ON), skipping stale serve");
                 // Fallthrough to Miss
            } else if remaining > 0 || can_serve_stale {
                if is_stale {
                     debug!("🧟 Serving STALE cache for hash={:x} (Expired {}s ago)", key.name_hash, elapsed - original_ttl);
                } else {
                     debug!("✅ Cache HIT for hash={:x} (TTL: {}s)", key.name_hash, remaining);
                }

                // [ZERO-COPY] Try to use pre-serialized bytes if available
                if let Some(ref raw_bytes) = cached_entry.raw_bytes {
                    // Use ZeroCopyDnsMessage for fast response
                    if let Ok(zc_msg) = crate::core::zerocopy::ZeroCopyDnsMessage::from_bytes(raw_bytes.clone()) {
                        ctx.set_raw_response(zc_msg, true);
                        debug!("⚡ Zero-copy cache response sent");
                    } else {
                        // Fallback to parsed Message
                        let mut response_msg = cached_entry.message.as_ref().clone();
                        response_msg.set_id(ctx.request.id());
                        ctx.set_response(response_msg, true);
                    }
                } else {
                    // No pre-serialized bytes, use Message
                    let mut response_msg = cached_entry.message.as_ref().clone();
                    response_msg.set_id(ctx.request.id());
                    ctx.set_response(response_msg, true);
                }
                
                // --- Smart Prefetch Trigger ---
                // Trigger if: (Fresh but low TTL) OR (Stale)
                let need_prefetch = (remaining > 0 && remaining < self.prefetch_threshold) || is_stale;
                
                if need_prefetch {
                    // Priority 1: Recursive Refresh (Trusted/Iterative)
                    if let Some(recursive) = &self.prefetch_recursive {
                         debug!("⚡ Triggering background RECURSIVE refresh for hash={:x}", key.name_hash);
                         let recursive_clone = recursive.clone();
                         let cache_clone = self.cache.clone();
                         let key_clone = key.clone();
                         
                         // We need the domain name string for lookup
                         if let Some(query) = ctx.request.query() {
                             let name_str = query.name().to_string();
                             let qtype = u16::from(query.query_type());
                             let myself = self.clone(); // For calculate_ttl
                             let forwarder_backup = self.prefetch_forwarder.clone(); // Backup
                             let req_clone_for_backup = if forwarder_backup.is_some() { Some(ctx.request.clone()) } else { None };

                             tokio::spawn(async move {
                                 // Jitter: Wait 0-300ms to avoid network burst
                                 use rand::Rng;
                                 let jitter = rand::thread_rng().gen_range(0..300);
                                 tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;

                                 // Try Recursive First
                                 match recursive_clone.lookup(&name_str, qtype).await {
                                     Ok(msg) => {
                                         let ttl = myself.calculate_ttl(&msg);
                                         if ttl > 0 {
                                             let msg_bytes = match msg.to_vec() {
                                                 Ok(b) => b,
                                                 Err(e) => {
                                                     warn!("⚠️ Recursive refresh encode failed for {}: {}", name_str, e);
                                                     return;
                                                 }
                                             };
                                             let raw_bytes = bytes::Bytes::from(msg_bytes);
                                             let entry = CachedEntry::new_with_bytes(msg, ttl, raw_bytes);
                                             cache_clone.insert(key_clone, entry).await;
                                             debug!("✅ Recursive refresh UPDATED: {} (TTL: {}s)", name_str, ttl);
                                         }
                                     },
                                     Err(e) => {
                                          warn!("⚠️ Recursive refresh FAILED for {}: {}. Trying Fallback...", name_str, e);
                                          // Fallback to Forwarder
                                          if let Some(fwd) = forwarder_backup {
                                              if let Some(req) = req_clone_for_backup {
                                                  match fwd.execute(&req, None).await {
                                                      Ok(resp) => {
                                                          let ttl = myself.calculate_ttl(&resp);
                                                          if ttl > 0 {
                                                              let resp_bytes = match resp.to_vec() {
                                                                  Ok(b) => b,
                                                                  Err(e) => {
                                                                      warn!("⚠️ Fallback refresh encode failed for {}: {}", name_str, e);
                                                                      return;
                                                                  }
                                                              };
                                                              let raw_bytes = bytes::Bytes::from(resp_bytes);
                                                              let entry = CachedEntry::new_with_bytes(resp, ttl, raw_bytes);
                                                              cache_clone.insert(key_clone.clone(), entry).await; // key_clone was moved? No, Copy? QueriesKey is Clone.
                                                              debug!("🔄 Fallback refresh UPDATED: {} (TTL: {}s)", name_str, ttl);
                                                          }
                                                      },
                                                      Err(e2) => warn!("❌ Fallback also FAILED for {}: {}", name_str, e2),
                                                  }
                                              }
                                          }
                                     }
                                 }
                             });
                         }
                    } 
                    // Priority 2: Forwarder Prefetch (Legacy)
                    else if let Some(forwarder) = &self.prefetch_forwarder {
                         debug!("⚡ Triggering background FORWARD prefetch for hash={:x}", key.name_hash);
                         let forwarder_clone = forwarder.clone();
                         let cache_clone = self.cache.clone();
                         let req_clone = ctx.request.clone();
                         let key_clone = key.clone();
                         let myself = self.clone(); 
                         
                         tokio::spawn(async move {
                                 match forwarder_clone.execute(&req_clone, None).await {
                                  Ok(resp) => {
                                      let ttl = myself.calculate_ttl(&resp);
                                      if ttl > 0 {
                                          let resp_bytes = match resp.to_vec() {
                                              Ok(b) => b,
                                              Err(e) => {
                                                  warn!("⚠️ Prefetch encode failed for hash={:x}: {}", key_clone.name_hash, e);
                                                  return;
                                              }
                                          };
                                          let raw_bytes = bytes::Bytes::from(resp_bytes);
                                          let entry = CachedEntry::new_with_bytes(resp, ttl, raw_bytes);
                                          cache_clone.insert(key_clone.clone(), entry).await;
                                          debug!("⚡ Prefetch UPDATED hash={:x} (New TTL: {}s)", key_clone.name_hash, ttl);
                                      }
                                  },
                                 Err(e) => {
                                     warn!("⚡ Prefetch FAILED for hash={:x}: {}", key_clone.name_hash, e);
                                 }
                             }
                         });
                    }
                }
                
                return Ok(());
            } else {
                 debug!("💀 Cache entry EXPIRED for hash={:x} (Too old for Stale), dropped", key.name_hash);
                 self.cache.invalidate(&key).await;
            }
        }

        // 2. Miss -> Register Hook for Write-back
        debug!("❌ Cache MISS for hash={:x}", key.name_hash);
        metrics::inc_cache_miss();
        STATS.record_cache_miss();
        
        // Use AnyPlugin wrapper
        let hook_variant = AnyPlugin::Cache(Arc::new(self.clone()));
        ctx.post_process_hooks.push(hook_variant);
        
        Ok(())
    }

    async fn on_response(&self, ctx: &mut Context) -> Result<()> {
        let key = match self.get_key(ctx) {
            Some(k) => k,
            None => return Ok(()),
        };

        if let Some(resp) = &ctx.response {
            // Validate cache entry size
            const MAX_CACHE_ENTRY_SIZE: usize = 4096; // Increased for larger records
            let response_bytes = resp.to_vec().unwrap_or_default();
            if response_bytes.len() > MAX_CACHE_ENTRY_SIZE {
                return Ok(());
            }
            
            // Calculate TTL
            let ttl = self.calculate_ttl(resp);

            if ttl > 0 {
                debug!("💾 Caching response (TTL: {}s)", ttl);
                // 使用 CachedEntry 包装，记录插入时间和 TTL
                let raw_bytes = bytes::Bytes::from(response_bytes);
                let entry = CachedEntry::new_with_bytes(resp.clone(), ttl, raw_bytes.clone());
                self.cache.insert(key.clone(), entry).await;
                
                // Sync hot entries to XDP kernel cache
                #[cfg(target_os = "linux")]
                if let Some(query) = ctx.request.query() {
                    let mut qname_raw = Vec::new();
                    let mut encoder = BinEncoder::new(&mut qname_raw);
                    if query.name().emit(&mut encoder).is_ok() {
                        let qtype: u16 = query.query_type().into();
                        let qclass: u16 = query.query_class().into();
                        let domain = query.name().to_string();
                        self.sync_to_xdp(&qname_raw, qtype, qclass, &domain, raw_bytes.as_ref(), ttl).await;
                    }
                }
            }
        }
        Ok(())
    }
}

// Make CachePlugin Cloneable (Cheap copy of Arc internals)
impl Clone for CachePlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            cache: self.cache.clone(), // Moka cache clone is cheap
            min_ttl: self.min_ttl,
            max_ttl: self.max_ttl,
            fakeip_protection: self.fakeip_protection,
            prefetch_forwarder: self.prefetch_forwarder.clone(),
            prefetch_recursive: self.prefetch_recursive.clone(),
            prefetch_threshold: self.prefetch_threshold,
            serve_stale_ttl: self.serve_stale_ttl,
            persist_file: self.persist_file.clone(),
            persist_interval: self.persist_interval,
            cache_warmer: self.cache_warmer.clone(),
            #[cfg(target_os = "linux")]
            xdp_filter: self.xdp_filter.clone(),
            xdp_cache_enabled: self.xdp_cache_enabled,
            xdp_hash_map: self.xdp_hash_map.clone(),
            #[cfg(target_os = "linux")]
            xdp_refresh_task_mgr: None,
        }
    }
}
