pub mod context;
pub mod plugin;
pub mod geosite_proto;
pub mod geoip_proto;
pub mod singleflight;
pub mod simd_hash;
pub mod aligned;
pub mod const_map;
pub mod zerocopy;
pub mod arena;
pub mod lockfree;
pub mod health;  // 上游健康度追踪
pub mod metrics; // Prometheus Metrics
pub mod hot_reload; // [NEW] Ghost Reload Core
pub mod task_manager; // Background task manager
