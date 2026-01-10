use crate::core::context::Context;
use crate::core::plugin::Plugin;
use tracing::{info, warn};
use hickory_proto::op::{ResponseCode, MessageType};
use crate::stats::STATS;
use anyhow::Result;

// Shannon Entropy Calculation
fn calculate_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let len = s.len() as f64;
    
    if len == 0.0 {
        return 0.0;
    }

    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// DGA (Domain Generation Algorithm) Detection Plugin
/// Uses statistical heuristics (Shannon Entropy) to identify and block potential malicious domains.
#[derive(Debug)]
pub struct DGAPlugin {
    name: String,
    entropy_threshold: f64,
    min_len: usize,
    dry_run: bool,
}

impl DGAPlugin {
    pub fn new(name: String, entropy_threshold: f64, min_len: usize, dry_run: bool) -> Self {
        info!("🛡️ DGA Filter initialized: threshold={}, min_len={}, dry_run={}", 
            entropy_threshold, min_len, dry_run);
        Self {
            name,
            entropy_threshold,
            min_len,
            dry_run,
        }
    }

    // Helper to get effective SLD (longest label)
    fn get_main_part<'a>(&self, ctx: &'a Context) -> &'a str {
        let mut best = "";
        for part in ctx.qname_parts_iter() {
            if part.len() > best.len() {
                best = part;
            }
        }
        if best.is_empty() {
            ctx.qname_lower_ref()
        } else {
            best
        }
    }
}

impl Plugin for DGAPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let qname = ctx.qname_ref();

        // Remove trailing dot for analysis
        let clean_name = qname.trim_end_matches('.');

        // Find the most significant part (the longest label)
        // DGA usually generates a long random string as the SLD
        let target_label = self.get_main_part(ctx);
        
        if target_label.len() < self.min_len {
            return Ok(()); // Too short to be confident
        }

        let entropy = calculate_entropy(target_label);
        
        // Debug logging for tuning
        // debug!("DGA Check: {} (label: {}) -> Entropy: {:.4}", clean_name, target_label, entropy);

        if entropy > self.entropy_threshold {
            
            if self.dry_run {
                warn!("🚨 DGA Detected (Dry Run): {} (Entropy: {:.2})", clean_name, entropy);
                return Ok(());
            }

            // Record as blocked
            STATS.record_blocked(clean_name);
            STATS.record_strategy("Blocked_DGA");

            warn!("🚫 DGA Blocked: {} (Entropy: {:.2} > {})", clean_name, entropy, self.entropy_threshold);
            
            // Build NXDOMAIN response
            // We use the Message path here since blocking is rare, 
            // but we could use a static raw response in future.
            let mut response = ctx.request.clone();
            response.set_message_type(MessageType::Response); // Fix make_response
            response.set_response_code(ResponseCode::NXDomain);
            
            ctx.set_response(response, true); // Stop processing
        }

        Ok(())
    }
}
