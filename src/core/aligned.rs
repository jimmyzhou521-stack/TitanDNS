// Cache-Line Aligned Structures
// Eliminates False Sharing for better multi-core performance

use std::sync::atomic::{AtomicU64, Ordering};

/// Cache line size on most modern CPUs
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line aligned atomic counter
/// Prevents false sharing between CPU cores
#[repr(align(64))]
pub struct AlignedCounter {
    value: AtomicU64,
    _padding: [u8; 56], // 64 - 8 = 56 bytes padding
}

impl AlignedCounter {
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
            _padding: [0; 56],
        }
    }

    #[inline]
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn set(&self, val: u64) {
        self.value.store(val, Ordering::Relaxed);
    }
}

/// Statistics with cache-line aligned fields
/// Each counter on its own cache line for optimal performance
#[repr(C)]
pub struct AlignedStats {
    pub cache_hits: AlignedCounter,
    pub cache_misses: AlignedCounter,
    pub queries_total: AlignedCounter,
    pub errors: AlignedCounter,
}

impl AlignedStats {
    pub fn new() -> Self {
        Self {
            cache_hits: AlignedCounter::new(0),
            cache_misses: AlignedCounter::new(0),
            queries_total: AlignedCounter::new(0),
            errors: AlignedCounter::new(0),
        }
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.increment();
        self.queries_total.increment();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.increment();
        self.queries_total.increment();
    }

    pub fn record_error(&self) {
        self.errors.increment();
    }

    pub fn get_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.get() as f64;
        let total = self.queries_total.get() as f64;
        if total > 0.0 {
            hits / total
        } else {
            0.0
        }
    }
}

impl Default for AlignedStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_aligned_counter() {
        let counter = AlignedCounter::new(0);
        counter.increment();
        counter.increment();
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_concurrent_increments() {
        let stats = std::sync::Arc::new(AlignedStats::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing 1000 times
        for _ in 0..10 {
            let stats_clone = stats.clone();
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    stats_clone.record_cache_hit();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stats.cache_hits.get(), 10000);
        assert_eq!(stats.queries_total.get(), 10000);
    }

    #[test]
    fn test_stats_alignment() {
        // Verify cache line alignment
        let stats = Box::new(AlignedStats::new());
        let ptr = &stats.cache_hits as *const AlignedCounter as usize;
        assert_eq!(ptr % CACHE_LINE_SIZE, 0, "cache_hits should be cache-line aligned");
    }
}
