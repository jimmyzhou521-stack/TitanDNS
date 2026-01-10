// eBPF DNS Filter Framework (Linux only)
// Provides kernel-level packet filtering for DDoS protection
// Using XDP (eXpress Data Path) for ultra-low latency

#![allow(dead_code)] // Framework implementation

#[cfg(target_os = "linux")]
use aya::Bpf;
#[cfg(target_os = "linux")]
use aya::programs::{Xdp, XdpFlags};
#[cfg(target_os = "linux")]
use tracing::info;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
pub struct DnsBpfFilter {
    interface: String,
    #[allow(dead_code)]
    bpf: Option<Bpf>,
}

#[cfg(target_os = "linux")]
impl DnsBpfFilter {
    /// Create a new eBPF filter
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            bpf: None,
        }
    }

    /// Load and attach eBPF program
    pub fn load_and_attach(&mut self, bpf_program_path: &Path) -> anyhow::Result<()> {
        info!("Loading eBPF DNS filter from {:?} for interface: {}", bpf_program_path, self.interface);

        // Load the compiled eBPF bytecode
        let mut bpf = Bpf::load_file(bpf_program_path)
            .map_err(|e| anyhow::anyhow!("Failed to load eBPF file: {}", e))?;
        info!("Object file loaded. Finding program...");

        // Get the XDP program (matches function name in C code)
        let program: &mut Xdp = bpf
            .program_mut("titan_dns_filter")
            .ok_or_else(|| anyhow::anyhow!("XDP program 'titan_dns_filter' not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert program to XDP: {}", e))?;
        
        info!("Program found. Loading into kernel (verifier)...");

        // Load the program into kernel
        program.load()
            .map_err(|e| anyhow::anyhow!("Failed to load XDP program into kernel: {}", e))?;
        
        info!("Program verified and loaded. Attaching to {}...", self.interface);

        // Attach to network interface
        // Use SKB mode for better compatibility (especially on 'lo' and VMs)
        program.attach(&self.interface, XdpFlags::SKB_MODE)
            .map_err(|e| anyhow::anyhow!("Failed to attach XDP program to {}: {}", self.interface, e))?;

        self.bpf = Some(bpf);
        
        info!("✅ eBPF DNS filter loaded and attached to {}", self.interface);
        
        Ok(())
    }

    /// Populate the kernel blacklist map from configuration
    pub fn populate_blacklist(&mut self, entries: &[crate::config::BlacklistEntry]) -> anyhow::Result<()> {
        use aya::maps::HashMap;
        
        if entries.is_empty() {
            return Ok(());
        }
        
        let bpf = self.bpf.as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;
        
        let mut map: HashMap<_, u32, u8> = bpf
            .map_mut("blacklist")
            .ok_or_else(|| anyhow::anyhow!("Map 'blacklist' not found in BPF"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to access blacklist map: {:?}", e))?;
        
        for entry in entries {
            let ip: std::net::Ipv4Addr = entry.ip.parse()
                .map_err(|e| anyhow::anyhow!("Invalid IP '{}': {}", entry.ip, e))?;
            
            let action: u8 = match entry.action.to_lowercase().as_str() {
                "refuse" => 2,
                _ => 1, // drop
            };
            
            let ip_u32 = u32::from(ip);
            map.insert(ip_u32, action, 0)
                .map_err(|e| anyhow::anyhow!("Failed to insert IP: {:?}", e))?;
            
            info!("🛡️ Kernel Blacklist: {} -> {}", entry.ip, entry.action);
        }
        
        info!("✅ Loaded {} IPs into kernel firewall", entries.len());
        Ok(())
    }

    /// Update XDP cache with a DNS response
    /// This allows hot queries to be answered directly from the kernel
    pub fn update_cache(&mut self, qname_raw: &[u8], qtype: u16, qclass: u16, response: &[u8], ttl_secs: u64) -> anyhow::Result<()> {
        use aya::maps::HashMap;
        
        let bpf = self.bpf.as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;
        
        let mut cache: HashMap<_, u64, DnsCacheEntry> = bpf
            .map_mut("dns_cache")
            .ok_or_else(|| anyhow::anyhow!("Map 'dns_cache' not found in BPF"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to access dns_cache map: {:?}", e))?;
        
        // Rich Hashing: Hash raw QNAME + QTYPE (2B) + QCLASS (2B) using DJB2
        let mut qhash = djb2_hash_bytes(qname_raw);
        qhash = djb2_hash_bytes_incremental(qhash, &qtype.to_be_bytes());   // QTYPE
        qhash = djb2_hash_bytes_incremental(qhash, &qclass.to_be_bytes());  // QCLASS

        let mut entry = DnsCacheEntry::default();
        
        // Copy response (without transaction ID - will be filled on cache hit)
        // Safety: Limit to MAX_DNS_RESPONSE_LEN to prevent buffer overflow
        let copy_len = response.len().min(768); 
        entry.response[..copy_len].copy_from_slice(&response[..copy_len]);
        entry.len = copy_len as u16;
        
        // Set expiration (convert to nanoseconds since boot)
        let now_ns = get_kernel_time_ns();
        entry.expire_ns = now_ns + (ttl_secs + 60) * 1_000_000_000;
        
        // Initialize last_refresh_ts to current time to prevent immediate refresh trigger
        entry.last_refresh_ts = (now_ns / 1_000_000_000) as u32;
        
        // Extract RCODE from response flags
        if response.len() >= 4 { entry.rcode = (response[3] & 0x0F) as u16; }

        // Insert into kernel cache using the u64 rich hash
        info!("XDP Sync: h={:x} len={} rcode={}", qhash, entry.len, entry.rcode);
        cache.insert(qhash, entry, 0)
            .map_err(|e| anyhow::anyhow!("Failed to insert cache entry: {:?}", e))?;
        
        Ok(())
    }

    /// Get XDP cache statistics
    pub fn get_cache_stats(&self) -> anyhow::Result<XdpCacheStats> {
        use aya::maps::PerCpuArray;
        
        let bpf = self.bpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;
        
        let stats_map: PerCpuArray<_, u64> = bpf
            .map("stats")
            .ok_or_else(|| anyhow::anyhow!("Stats map not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to access stats map: {:?}", e))?;
        
        // Sum across all CPUs
        let mut result = XdpCacheStats::default();
        
        // STAT_CACHE_HIT = 2
        if let Ok(vals) = stats_map.get(&2, 0) {
            result.cache_hits = vals.iter().sum();
        }
        
        // STAT_CACHE_MISS = 3
        if let Ok(vals) = stats_map.get(&3, 0) {
            result.cache_misses = vals.iter().sum();
        }
        
        // STAT_CACHE_EXPIRED = 4 (Note: now shadow_refresh uses 4)
        // Keep expired at 3 for backward compatibility, shadow_refresh at 4
        if let Ok(vals) = stats_map.get(&4, 0) {
            result.shadow_refreshes = vals.iter().sum();
        }
        
        Ok(result)
    }

    /// Detach eBPF program
    pub fn detach(&mut self) -> anyhow::Result<()> {
        if self.bpf.is_some() {
            info!("Detaching eBPF DNS filter from {}", self.interface);
            // Automatic cleanup when bpf is dropped
            self.bpf = None;
        }
        Ok(())
    }

    /// Start Shadow Refresh listener
    /// This spawns a background task that listens for refresh events from XDP
    /// and calls the provided callback with the query hash that needs refreshing
    pub fn start_refresh_listener<F>(&mut self, _callback: F) -> anyhow::Result<()>
    where
        F: Fn(u64) + Send + Sync + 'static,
    {
        // NOTE:
        // The active polling loop is implemented in CachePlugin::set_xdp_filter,
        // which calls poll_refresh_events() periodically.
        // This method is kept for API compatibility.
        info!("🔄 Shadow Refresh listener registered (handled by CachePlugin poller)");
        Ok(())
    }

    /// Poll Shadow Refresh ring buffer (called from stats task)
    /// Returns the number of refresh events processed
    pub fn poll_refresh_events<F>(&mut self, callback: F) -> usize
    where
        F: Fn(u64),
    {
        use aya::maps::RingBuf;
        
        let bpf = match self.bpf.as_mut() {
            Some(b) => b,
            None => return 0,
        };
        
        let ringbuf = match bpf.map_mut("refresh_ringbuf") {
            Some(r) => r,
            None => return 0,
        };
        
        let mut ring: RingBuf<_> = match ringbuf.try_into() {
            Ok(r) => r,
            Err(_) => return 0,
        };
        
        let mut count = 0;
        const MAX_EVENTS_PER_POLL: usize = 10; // Limit to prevent CPU spike
        
        while let Some(item) = ring.next() {
            if count >= MAX_EVENTS_PER_POLL {
                break; // Process remaining events in next poll cycle
            }
            if item.len() >= std::mem::size_of::<RefreshEvent>() {
                let event: RefreshEvent = unsafe {
                    std::ptr::read_unaligned(item.as_ptr() as *const RefreshEvent)
                };
                callback(event.qhash);
                count += 1;
            }
        }
        count
    }

    /// Get statistics from eBPF program
    pub fn get_stats(&self) -> BpfStats {
        if let Some(bpf) = &self.bpf {
            // Try to read stats map
            // Note: This requires proper map access
            if let Some(_map) = bpf.map("STATS") {
                // Read statistics
                // This is a simplified version - actual implementation would read from HashMap
                return BpfStats {
                    packets_filtered: 0,  // Would read from map key 4
                    packets_passed: 0,     // Would calculate
                    bytes_filtered: 0,     // Would calculate
                };
            }
        }
        
        BpfStats::default()
    }
}

/// Start a standalone Shadow Refresh polling task for DnsBpfFilter.
/// This can be used in environments without CachePlugin polling.
#[cfg(target_os = "linux")]
pub fn start_refresh_listener_task<F>(
    filter: std::sync::Arc<tokio::sync::Mutex<DnsBpfFilter>>,
    callback: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    let callback = std::sync::Arc::new(callback);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Ok(mut guard) = filter.try_lock() {
                let cb = callback.clone();
                let _ = guard.poll_refresh_events(|qhash| (cb)(qhash));
            }
        }
    })
}

#[cfg(target_os = "linux")]
impl Drop for DnsBpfFilter {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BpfStats {
    pub packets_filtered: u64,
    pub packets_passed: u64,
    pub bytes_filtered: u64,
}

// XDP Cache Entry (must match C struct layout EXACTLY)
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_os = "linux")]
pub struct DnsCacheEntry {
    pub len: u16,            // 0-2
    pub rcode: u16,          // 2-4 (Changed to u16 to match C)
    pub last_refresh_ts: u32,  // 4-8 (Was padding)
    pub expire_ns: u64,      // 8-16
    pub response: [u8; 768], // 16-784 (Extended for CDN responses)
}

// SAFETY: DnsCacheEntry is repr(C), contains only Copy types, and has no padding issues
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for DnsCacheEntry {}

#[cfg(target_os = "linux")]
impl Default for DnsCacheEntry {
    fn default() -> Self {
        Self {
            len: 0,
            rcode: 0,
            last_refresh_ts: 0,
            expire_ns: 0,
            response: [0; 768],
        }
    }
}

// XDP Cache Statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpCacheStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_expired: u64,
    pub shadow_refreshes: u64,  // Shadow Refresh triggered count
}

// Shadow Refresh Event (must match C struct layout)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg(target_os = "linux")]
pub struct RefreshEvent {
    pub qhash: u64,        // Query hash to refresh
    pub remaining_ns: u64, // Remaining TTL in nanoseconds
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for RefreshEvent {}

#[cfg(target_os = "linux")]
fn djb2_hash_bytes(data: &[u8]) -> u64 {
    djb2_hash_bytes_incremental(5381, data)
}

#[cfg(target_os = "linux")]
fn djb2_hash_bytes_incremental(mut hash: u64, data: &[u8]) -> u64 {
    // DJB2: hash = hash * 33 + byte = (hash << 5) + hash + byte
    for &byte in data {
        let mut b = byte;
        if b >= b'A' && b <= b'Z' { b += 32; }
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(b as u64);
    }
    hash
}

// Approximate kernel time (ns since boot)
// Note: bpf_ktime_get_ns() measures time since boot (CLOCK_MONOTONIC)
#[cfg(target_os = "linux")]
fn get_kernel_time_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

// Non-Linux platforms: provide stub implementation
#[cfg(not(target_os = "linux"))]
pub struct DnsBpfFilter {
    interface: String,
}

#[cfg(not(target_os = "linux"))]
impl DnsBpfFilter {
    pub fn new(interface: String) -> Self {
        eprintln!("⚠️  eBPF filtering is only available on Linux");
        Self { interface }
    }

    pub fn load_and_attach(&mut self, _bpf_program_path: &std::path::Path) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("eBPF is not supported on this platform"))
    }

    pub fn detach(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn get_stats(&self) -> BpfStats {
        BpfStats::default()
    }

    // Add stub for update_cache
    pub fn update_cache(&mut self, _qname_raw: &[u8], _qtype: u16, _qclass: u16, _response: &[u8], _ttl_secs: u64) -> anyhow::Result<()> {
        Ok(())
    }
    
    // Add stub for get_cache_stats
    pub fn get_cache_stats(&self) -> anyhow::Result<XdpCacheStats> {
        Ok(XdpCacheStats::default())
    }
    
    // Add stub for populate_blacklist
    pub fn populate_blacklist(&mut self, _entries: &[crate::config::BlacklistEntry]) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_filter_creation() {
        let filter = DnsBpfFilter::new("lo".to_string());
        assert_eq!(filter.interface, "lo");
    }

    #[test]
    fn test_bpf_stats_default() {
        let stats = BpfStats::default();
        assert_eq!(stats.packets_filtered, 0);
        assert_eq!(stats.packets_passed, 0);
        assert_eq!(stats.bytes_filtered, 0);
    }
}
