use anyhow::Result;
use tracing::{debug, info, error};
use std::sync::Arc;
use std::net::IpAddr;
use maxminddb::geoip2;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use once_cell::sync::OnceCell;

use crate::core::context::Context;
use crate::core::plugin::Plugin;

#[derive(Clone)]
pub enum GeoIpMode {
    Client,
    Response,
}

pub struct GeoIpPlugin {
    pub name: String,
    reader: Arc<OnceCell<maxminddb::Reader<Vec<u8>>>>,
    mode: GeoIpMode,
    country_code: String,
    tag: String,
    invert: bool,
    // [NEW] IP 查询结果缓存 (无锁高性能)
    ip_cache: DashMap<IpAddr, bool>,
    // [NEW] 统计
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl GeoIpPlugin {
    /// Create a new GeoIpPlugin that loads the MMDB file in the background.
    /// The plugin is immediately usable, but will skip matching until loading completes.
    pub fn new_async(file: &str, code: &str, tag: &str, mode: GeoIpMode) -> Self {
        let reader = Arc::new(OnceCell::new());
        let reader_clone = reader.clone();
        let file_path = file.to_string();
        
        // Load MMDB in background thread (blocking I/O)
        tokio::task::spawn_blocking(move || {
            match maxminddb::Reader::open_readfile(&file_path) {
                Ok(r) => {
                    let _ = reader_clone.set(r);
                    info!("🗺️ GeoIP database loaded: {}", file_path);
                }
                Err(e) => {
                    error!("❌ Failed to load GeoIP database {}: {}", file_path, e);
                }
            }
        });
        
        Self {
            name: "geoip".to_string(),
            reader,
            mode,
            country_code: code.to_lowercase(),
            tag: tag.to_string(),
            invert: false,
            ip_cache: DashMap::with_capacity(10000),  // Pre-allocate for 10k IPs
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }
    
    /// Sync constructor for backwards compatibility (blocks on load)
    pub fn new(file: &str, code: &str, tag: &str, mode: GeoIpMode) -> Result<Self> {
        let r = maxminddb::Reader::open_readfile(file)?;
        let cell = OnceCell::new();
        let _ = cell.set(r);
        Ok(Self {
            name: "geoip".to_string(),
            reader: Arc::new(cell),
            mode,
            country_code: code.to_lowercase(),
            tag: tag.to_string(),
            invert: false,
            ip_cache: DashMap::with_capacity(10000),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        })
    }

    pub fn with_invert(mut self, invert: bool) -> Self {
        self.invert = invert;
        self
    }

    pub async fn is_match(&self, ip: IpAddr) -> bool {
        self.check_ip(ip).await
    }

    async fn check_ip(&self, ip: IpAddr) -> bool {
        // [FAST PATH] Check cache first (DashMap, ~50ns)
        if let Some(cached) = self.ip_cache.get(&ip) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return *cached;
        }
        
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // [SLOW PATH] Query MMDB (~10-50μs)
        let result = {
            if let Some(reader) = self.reader.get() {
                match reader.lookup::<geoip2::Country>(ip) {
                    Ok(country) => {
                        if let Some(c) = country.country {
                            if let Some(iso_code) = c.iso_code {
                                iso_code.to_lowercase() == self.country_code
                            } else { false }
                        } else { false }
                    },
                    Err(_) => false,
                }
            } else {
                // Reader not loaded yet, skip matching
                return false;
            }
        };
        
        // Cache the result for future queries
        self.ip_cache.insert(ip, result);
        
        result
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (u64, u64, f64) {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 { hits as f64 / total as f64 * 100.0 } else { 0.0 };
        (hits, misses, hit_rate)
    }
}

// Manual Debug because maxminddb::Reader might not implement it properly or we just don't want to dump DB
impl std::fmt::Debug for GeoIpPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpPlugin")
         .field("name", &self.name)
         .field("code", &self.country_code)
         .field("tag", &self.tag)
         .finish()
    }
}

impl Plugin for GeoIpPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let matched = match self.mode {
            GeoIpMode::Client => {
                self.check_ip(ctx.client_addr.ip()).await
            },

            GeoIpMode::Response => {
                // If response exists and has A/AAAA records
                let mut found = false;
                if let Some(resp) = &ctx.response {
                     for ans in resp.answers() {
                         let data = ans.data(); 
                         if let Some(a) = data.as_a() {
                             if self.check_ip(IpAddr::V4(a.0)).await { found = true; break; }
                         } else if let Some(aaaa) = data.as_aaaa() {
                             if self.check_ip(IpAddr::V6(aaaa.0)).await { found = true; break; }
                         }
                     }
                }
                found
            }
        };

        if (matched && !self.invert) || (!matched && self.invert) {
            debug!("GeoIP matched! Adding tag: {}", self.tag);
            ctx.add_tag(&self.tag);
        }

        Ok(())
    }
}
