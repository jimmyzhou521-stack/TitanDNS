use crate::core::context::Context;
use crate::core::plugin::Plugin;
use anyhow::Result;
use tracing::{info, debug};
use hickory_proto::op::{Message, ResponseCode, MessageType, OpCode};
use hickory_proto::rr::RecordType;

/// IPv6 Filter Plugin
/// Controls IPv4/IPv6 priority for DNS responses
#[derive(Clone, Debug)]
pub struct Ipv6FilterPlugin {
    name: String,
    mode: Ipv6FilterMode,
    delay_aaaa_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Ipv6FilterMode {
    /// Delay AAAA responses to prefer IPv4
    PreferIpv4,
    /// Delay A responses to prefer IPv6
    PreferIpv6,
    /// Return empty response for AAAA queries
    DisableIpv6,
    /// Do nothing
    Disabled,
}

impl Ipv6FilterPlugin {
    pub fn new(name: String, mode: &str, delay_aaaa_ms: u64) -> Result<Self> {
        let mode = match mode.to_lowercase().as_str() {
            "prefer_ipv4" => Ipv6FilterMode::PreferIpv4,
            "prefer_ipv6" => Ipv6FilterMode::PreferIpv6,
            "disable_ipv6" => Ipv6FilterMode::DisableIpv6,
            "disabled" | "" => Ipv6FilterMode::Disabled,
            _ => {
                info!("⚠️ Unknown ipv6_filter mode '{}', defaulting to disabled", mode);
                Ipv6FilterMode::Disabled
            }
        };

        info!("🌐 IPv6 Filter Plugin '{}' created (mode: {:?}, delay: {}ms)", 
              name, mode, delay_aaaa_ms);

        Ok(Self {
            name,
            mode,
            delay_aaaa_ms,
        })
    }
}

impl Plugin for Ipv6FilterPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // Skip if response already set or mode is disabled
        if ctx.response.is_some() || self.mode == Ipv6FilterMode::Disabled {
            return Ok(());
        }

        if let Some(query) = ctx.request.query() {
            let qtype = query.query_type();

            match self.mode {
                Ipv6FilterMode::DisableIpv6 => {
                    // If query is AAAA, return empty NOERROR response
                    if qtype == RecordType::AAAA {
                        debug!("🌐 IPv6Filter: Blocking AAAA query for {}", query.name());
                        
                        let mut response = Message::new();
                        response.set_id(ctx.request.id());
                        response.set_op_code(OpCode::Query);
                        response.set_message_type(MessageType::Response);
                        response.set_response_code(ResponseCode::NoError);
                        response.set_recursion_available(true);
                        response.add_query(query.clone());
                        // No answer section = empty response
                        
                        ctx.response = Some(response);
                    }
                },
                Ipv6FilterMode::PreferIpv4 => {
                    // If query is AAAA, add delay before processing
                    if qtype == RecordType::AAAA && self.delay_aaaa_ms > 0 {
                        debug!("🌐 IPv6Filter: Delaying AAAA query for {} by {}ms", 
                               query.name(), self.delay_aaaa_ms);
                        tokio::time::sleep(tokio::time::Duration::from_millis(self.delay_aaaa_ms)).await;
                    }
                },
                Ipv6FilterMode::PreferIpv6 => {
                    // If query is A, add delay before processing
                    if qtype == RecordType::A && self.delay_aaaa_ms > 0 {
                        debug!("🌐 IPv6Filter: Delaying A query for {} by {}ms", 
                               query.name(), self.delay_aaaa_ms);
                        tokio::time::sleep(tokio::time::Duration::from_millis(self.delay_aaaa_ms)).await;
                    }
                },
                Ipv6FilterMode::Disabled => {},
            }
        }

        Ok(())
    }
}
