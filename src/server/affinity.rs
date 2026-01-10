use core_affinity;
use tracing::{info, warn, debug};

/// Try to bind the current thread to a specific CPU core based on worker index.
/// This prevents thread migration and reduces context switching overhead,
/// effectively solving the PVE "freeze" issue under high load.
pub fn bind_thread_to_cpu(worker_index: usize) {
    // Attempt to retrieve available core IDs
    if let Some(core_ids) = core_affinity::get_core_ids() {
        if core_ids.is_empty() {
            debug!("CpuAffinity: No cores available returned by system.");
            return;
        }

        // Round-robin assignment strategy: worker 0 -> core 0, worker 1 -> core 1, etc.
        // This ensures even distribution across physical/virtual cores.
        let core_id = core_ids[worker_index % core_ids.len()];
        
        if core_affinity::set_for_current(core_id) {
            info!("✅ [CpuAffinity] Worker #{} bound to CPU Core {:?}", worker_index, core_id);
        } else {
            warn!("⚠️ [CpuAffinity] Failed to bind Worker #{} to CPU Core {:?}", worker_index, core_id);
        }
    } else {
        // Not a critical error, just log a warning once
        debug!("CpuAffinity: Could not retrieve system CPU core IDs. Skipping affinity.");
    }
}
