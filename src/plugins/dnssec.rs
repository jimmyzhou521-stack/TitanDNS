// TitanDNS DNSSEC Validation Plugin
// Validates DNS responses using DNSSEC (RFC 4033-4035)
// Simplified implementation - checks AD flag and RRSIG presence

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// DNSSEC Validation Mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnssecMode {
    /// Validate and reject invalid responses
    Strict,
    /// Validate but allow responses (log warnings)
    Permissive,
    /// Only log DNSSEC status without validation
    LogOnly,
}

/// DNSSEC Validator Plugin
#[derive(Debug, Clone)]
pub struct DnssecPlugin {
    pub name: String,
    pub mode: DnssecMode,
    /// Trust anchors (root DNSKEY or DS records)
    #[allow(dead_code)]
    trust_anchors: Arc<Vec<TrustAnchor>>,
}

/// A DNSSEC trust anchor (root key)
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl DnssecPlugin {
    pub fn new(name: String, mode: String) -> Result<Self> {
        let validation_mode = match mode.to_lowercase().as_str() {
            "strict" => DnssecMode::Strict,
            "permissive" => DnssecMode::Permissive,
            "log" | "log_only" => DnssecMode::LogOnly,
            _ => DnssecMode::Permissive,
        };

        // Initialize with IANA root trust anchors
        // https://data.iana.org/root-anchors/root-anchors.xml
        let trust_anchors = vec![
            // Root KSK 2017 (Key Signing Key)
            TrustAnchor {
                key_tag: 20326,
                algorithm: 8,  // RSA/SHA-256
                digest_type: 2, // SHA-256
                digest: hex::decode(
                    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
                ).unwrap_or_default(),
            },
        ];

        info!("🔐 DNSSEC Plugin '{}' created (mode: {:?})", name, validation_mode);

        Ok(Self {
            name,
            mode: validation_mode,
            trust_anchors: Arc::new(trust_anchors),
        })
    }

    /// Check if response has DNSSEC records
    fn has_dnssec_records(msg: &Message) -> bool {
        msg.answers().iter().any(|r| {
            matches!(r.record_type(), RecordType::RRSIG | RecordType::DNSKEY | RecordType::DS)
        }) || msg.name_servers().iter().any(|r| {
            matches!(r.record_type(), RecordType::RRSIG | RecordType::DNSKEY | RecordType::DS | RecordType::NSEC | RecordType::NSEC3)
        })
    }

    /// Validate DNSSEC response (simplified)
    /// This implementation checks:
    /// 1. AD (Authentic Data) flag from resolver
    /// 2. Presence of DNSSEC-related records
    fn validate_response(&self, msg: &Message) -> DnssecStatus {
        // Check for AD (Authentic Data) flag - set by validating resolver
        if msg.authentic_data() {
            return DnssecStatus::Secure;
        }

        // Check if response has any DNSSEC records
        if Self::has_dnssec_records(msg) {
            // Has DNSSEC records but no AD flag - could be partial or failed validation
            // In a full implementation, we would verify signatures here
            return DnssecStatus::Indeterminate;
        }

        // No DNSSEC records at all - unsigned zone
        DnssecStatus::Insecure
    }
}

/// DNSSEC validation status
#[derive(Debug, Clone)]
pub enum DnssecStatus {
    /// Response is cryptographically verified (AD flag set)
    Secure,
    /// Response is not signed (unsigned zone)
    Insecure,
    /// Validation failed (do not trust)
    Bogus(String),
    /// Has DNSSEC records but couldn't fully validate
    Indeterminate,
}

impl Plugin for DnssecPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, _ctx: &mut Context) -> Result<()> {
        // DNSSEC validation happens on response, not request
        Ok(())
    }

    async fn on_response(&self, ctx: &mut Context) -> Result<()> {
        // Check if we have a response
        let response = match ctx.response.as_ref() {
            Some(r) => r,
            None => return Ok(()),
        };

        let status = self.validate_response(response);

        match (&status, self.mode) {
            (DnssecStatus::Secure, _) => {
                debug!("🔐 DNSSEC: Response is SECURE (AD flag set)");
                ctx.add_tag("dnssec_secure");
            }
            (DnssecStatus::Insecure, _) => {
                debug!("⚠️ DNSSEC: Response is INSECURE (unsigned zone)");
                ctx.add_tag("dnssec_insecure");
            }
            (DnssecStatus::Bogus(reason), DnssecMode::Strict) => {
                warn!("❌ DNSSEC: Response is BOGUS: {} - REJECTING", reason);
                ctx.add_tag("dnssec_bogus");
                
                // In strict mode, reject bogus responses
                let mut reject_msg = Message::new();
                reject_msg.set_id(ctx.request.id());
                reject_msg.set_response_code(ResponseCode::ServFail);
                ctx.response = Some(reject_msg);
            }
            (DnssecStatus::Bogus(reason), _) => {
                warn!("⚠️ DNSSEC: Response is BOGUS: {} - ALLOWING (permissive mode)", reason);
                ctx.add_tag("dnssec_bogus");
            }
            (DnssecStatus::Indeterminate, _) => {
                debug!("❓ DNSSEC: Has DNSSEC records but validation indeterminate");
                ctx.add_tag("dnssec_indeterminate");
            }
        }

        Ok(())
    }
}
