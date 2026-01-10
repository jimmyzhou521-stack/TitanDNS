use arc_swap::ArcSwap;
use std::sync::Arc;
use std::collections::HashMap;
use crate::plugins::AnyPlugin;

/// The structure that holds the current "World State" of plugins
/// This is immutable once created. Replacing it is atomic.
pub struct VersionedRegistry {
    pub entry_points: HashMap<String, AnyPlugin>,
    pub version: u64,
}

/// The Atomic Manager for Hot Reloading
/// Uses ArcSwap for lock-free, zero-latency reads.
pub struct HotReloadManager {
    registry: ArcSwap<VersionedRegistry>,
}

// Static assertions to ensure thread safety
// AnyPlugin must be Clone + Send + Sync for this to work
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_all() {
        assert_send::<HotReloadManager>();
        assert_sync::<HotReloadManager>();
    }
};

impl HotReloadManager {
    pub fn new(entry_points: HashMap<String, AnyPlugin>) -> Self {
        Self {
            registry: ArcSwap::from(Arc::new(VersionedRegistry {
                entry_points,
                version: 0, // Initial version
            })),
        }
    }

    /// Atomically update the world
    /// Call this from the Config Watcher thread.
    pub fn update(&self, entry_points: HashMap<String, AnyPlugin>, version: u64) {
        self.registry.store(Arc::new(VersionedRegistry {
            entry_points,
            version,
        }));
    }

    /// Get the current entry point (Fast, Lock-Free O(1))
    /// This is called by every Server Worker for every packet.
    pub fn get_entry(&self, name: &str) -> Option<AnyPlugin> {
        self.registry.load().entry_points.get(name).cloned()
    }
    
    /// Get current version (useful for debugging/logging)
    pub fn version(&self) -> u64 {
        self.registry.load().version
    }
}

