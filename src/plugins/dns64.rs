// TitanDNS DNS64 Plugin
// Converts IPv4 addresses to IPv6 using NAT64 prefix (64:ff9b::/96)
// Enables IPv6-only clients to access IPv4-only servers

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use anyhow::Result;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType, Name};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{debug, info};

/// DNS64 Plugin - Synthesizes AAAA records from A records
#[derive(Debug, Clone)]
pub struct Dns64Plugin {
    pub name: String,
    /// NAT64 prefix (default: 64:ff9b::/96)
    pub prefix: Ipv6Addr,
    /// Prefix length (default: 96)
    pub prefix_len: u8,
    /// Only synthesize if no AAAA records exist
    pub only_if_no_aaaa: bool,
}

impl Dns64Plugin {
    pub fn new(name: String, prefix: Option<String>, only_if_no_aaaa: bool) -> Result<Self> {
        // Parse prefix or use default NAT64 well-known prefix
        let (prefix_addr, prefix_len) = if let Some(p) = prefix {
            Self::parse_prefix(&p)?
        } else {
            // RFC 6052: Well-Known Prefix for IPv4/IPv6 Translation
            (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96)
        };

        info!("🔄 DNS64 Plugin '{}' created (prefix: {:?}/{}, only_if_no_aaaa: {})", 
              name, prefix_addr, prefix_len, only_if_no_aaaa);

        Ok(Self {
            name,
            prefix: prefix_addr,
            prefix_len,
            only_if_no_aaaa,
        })
    }

    fn parse_prefix(s: &str) -> Result<(Ipv6Addr, u8)> {
        let parts: Vec<&str> = s.split('/').collect();
        let addr: Ipv6Addr = parts[0].parse()
            .map_err(|e| anyhow::anyhow!("Invalid IPv6 prefix: {}", e))?;
        let len: u8 = parts.get(1)
            .map(|l| l.parse().unwrap_or(96))
            .unwrap_or(96);
        
        if len != 96 && len != 64 && len != 56 && len != 48 && len != 40 && len != 32 {
            return Err(anyhow::anyhow!("DNS64 prefix length must be 32, 40, 48, 56, 64, or 96"));
        }

        Ok((addr, len))
    }

    /// Synthesize IPv6 address from IPv4 using NAT64 prefix
    fn synthesize_ipv6(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let v4_octets = ipv4.octets();
        let prefix_octets = self.prefix.octets();

        match self.prefix_len {
            96 => {
                // Most common: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:a.b.c.d
                let mut octets = [0u8; 16];
                octets[..12].copy_from_slice(&prefix_octets[..12]);
                octets[12..16].copy_from_slice(&v4_octets);
                Ipv6Addr::from(octets)
            }
            64 => {
                // xxxx:xxxx:xxxx:xxxx:00ab:cdef:0000:0000
                let mut octets = [0u8; 16];
                octets[..8].copy_from_slice(&prefix_octets[..8]);
                octets[9] = v4_octets[0];
                octets[10] = v4_octets[1];
                octets[11] = v4_octets[2];
                octets[12] = v4_octets[3];
                Ipv6Addr::from(octets)
            }
            _ => {
                // Simplified: treat as /96
                let mut octets = [0u8; 16];
                octets[..12].copy_from_slice(&prefix_octets[..12]);
                octets[12..16].copy_from_slice(&v4_octets);
                Ipv6Addr::from(octets)
            }
        }
    }

    /// Check if response has any AAAA records
    fn has_aaaa_records(msg: &Message) -> bool {
        msg.answers().iter().any(|r| r.record_type() == RecordType::AAAA)
    }

    /// Extract A records from response
    fn get_a_records(msg: &Message) -> Vec<(Name, u32, Ipv4Addr)> {
        msg.answers()
            .iter()
            .filter_map(|r| {
                if r.record_type() == RecordType::A {
                    if let RData::A(a) = r.data() {
                        return Some((r.name().clone(), r.ttl(), a.0));
                    }
                }
                None
            })
            .collect()
    }
}

impl Plugin for Dns64Plugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // Only process AAAA queries
        if let Some(query) = ctx.request.query() {
            if query.query_type() != RecordType::AAAA {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Check if we already have a response
        let response = match ctx.response.as_ref() {
            Some(r) => r,
            None => return Ok(()),
        };

        // Check if already has AAAA records
        if self.only_if_no_aaaa && Self::has_aaaa_records(response) {
            debug!("DNS64: Response already has AAAA records, skipping synthesis");
            return Ok(());
        }

        // Get A records to synthesize from
        let a_records = Self::get_a_records(response);
        
        if a_records.is_empty() {
            debug!("DNS64: No A records to synthesize from");
            return Ok(());
        }

        // Build synthesized response
        let mut new_response = Message::new();
        new_response.set_id(ctx.request.id());
        new_response.set_message_type(MessageType::Response);
        new_response.set_op_code(response.op_code());
        new_response.set_response_code(ResponseCode::NoError);
        new_response.set_recursion_desired(true);
        new_response.set_recursion_available(true);

        // Copy query
        if let Some(q) = ctx.request.query() {
            new_response.add_query(q.clone());
        }

        // Synthesize AAAA records from A records
        let record_count = a_records.len();
        for (name, ttl, ipv4) in a_records {
            let ipv6 = self.synthesize_ipv6(ipv4);
            
            let record = Record::from_rdata(
                name.clone(),
                ttl,
                RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6))
            );

            new_response.add_answer(record);
            debug!("DNS64: Synthesized {} -> {} for {}", ipv4, ipv6, name);
        }

        // Copy authority and additional sections
        for ns in response.name_servers() {
            new_response.add_name_server(ns.clone());
        }
        for add in response.additionals() {
            new_response.add_additional(add.clone());
        }

        ctx.response = Some(new_response);
        info!("🔄 DNS64: Synthesized {} AAAA records", record_count);

        Ok(())
    }
}
