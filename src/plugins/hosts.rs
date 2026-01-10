// HOSTS Plugin
// Provides /etc/hosts style domain-to-IP mapping
// Useful for local overrides and custom DNS records

#![allow(dead_code)] // Framework implementation

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{debug, info, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

#[derive(Debug, Clone)]
pub struct HostsPlugin {
    pub name: String,
    hosts: HashMap<String, Vec<IpAddr>>,
}

impl HostsPlugin {
    pub fn new() -> Self {
        Self {
            name: "hosts".to_string(),
            hosts: HashMap::new(),
        }
    }

    /// Load hosts from file (e.g., /etc/hosts format)
    pub fn load_from_file(path: PathBuf) -> Result<Self> {
        let mut plugin = Self::new();
        
        let content = fs::read_to_string(&path)?;
        let mut line_count = 0;
        let mut record_count = 0;

        for line in content.lines() {
            line_count += 1;
            
            // Skip empty lines and comments
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse: <IP> <hostname> [<alias> ...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                warn!("Invalid hosts entry at line {}: {}", line_count, line);
                continue;
            }

            let ip_str = parts[0];
            let ip = match IpAddr::from_str(ip_str) {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Invalid IP address at line {}: {} ({})", line_count, ip_str, e);
                    continue;
                }
            };

            // Add entry for each hostname/alias
            for hostname in &parts[1..] {
                // Normalize to lowercase with trailing dot
                let normalized = if hostname.ends_with('.') {
                    hostname.to_lowercase()
                } else {
                    format!("{}.", hostname.to_lowercase())
                };

                plugin.hosts.entry(normalized.clone())
                    .or_insert_with(Vec::new)
                    .push(ip);
                
                record_count += 1;
            }
        }

        info!("Loaded {} hosts records from {} ({} lines)", 
              record_count, path.display(), line_count);

        Ok(plugin)
    }

    /// Add a single host entry
    pub fn add_host(&mut self, hostname: String, ip: IpAddr) {
        let normalized = if hostname.ends_with('.') {
            hostname.to_lowercase()
        } else {
            format!("{}.", hostname.to_lowercase())
        };

        self.hosts.entry(normalized)
            .or_insert_with(Vec::new)
            .push(ip);
    }

    /// Check if a hostname exists in hosts
    pub fn has_host(&self, hostname: &str) -> bool {
        let normalized = if hostname.ends_with('.') {
            hostname.to_lowercase()
        } else {
            format!("{}.", hostname.to_lowercase())
        };
        
        self.hosts.contains_key(&normalized)
    }

    /// Get IPs for a hostname
    pub fn get_ips(&self, hostname: &str) -> Option<&Vec<IpAddr>> {
        let normalized = if hostname.ends_with('.') {
            hostname.to_lowercase()
        } else {
            format!("{}.", hostname.to_lowercase())
        };
        
        self.hosts.get(&normalized)
    }

    /// Create DNS response from hosts entry
    fn create_response(&self, ctx: &Context, record_type: RecordType) -> Option<Message> {
        let query = ctx.request.query()?;
        let qname = ctx.qname_ref();
        
        let ips = self.get_ips(qname)?;

        let mut response = ctx.request.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);
        response.set_authoritative(true);

        let mut added = false;

        for ip in ips {
            match (ip, record_type) {
                (IpAddr::V4(ipv4), RecordType::A) => {
                    let record = Record::from_rdata(
                        query.name().clone(),
                        300, // TTL 5 minutes
                        RData::A((*ipv4).into()),
                    );
                    response.add_answer(record);
                    added = true;
                }
                (IpAddr::V6(ipv6), RecordType::AAAA) => {
                    let record = Record::from_rdata(
                        query.name().clone(),
                        300,
                        RData::AAAA((*ipv6).into()),
                    );
                    response.add_answer(record);
                    added = true;
                }
                _ => {} // Type mismatch, skip
            }
        }

        if added {
            Some(response)
        } else {
            // No matching records for this query type
            None
        }
    }
}

impl Default for HostsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for HostsPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let query = match ctx.request.query() {
            Some(q) => q,
            None => return Ok(()),
        };

        let qtype = query.query_type();
        let qname_ref = ctx.qname_ref();

        // Check if we have this host
        if !self.has_host(qname_ref) {
            return Ok(()); // Not in hosts, continue to next plugin
        }

        let qname = qname_ref.to_string();
        debug!("HOSTS: Found entry for {}", qname);

        // Only handle A and AAAA queries
        match qtype {
            RecordType::A | RecordType::AAAA => {
                if let Some(response) = self.create_response(ctx, qtype) {
                    debug!("HOSTS: Returning {} answer(s) for {}", 
                           response.answer_count(), qname);
                    ctx.set_response(response, true); // Stop sequence
                } else {
                    debug!("HOSTS: No {} records for {}", qtype, qname);
                    // Continue to next plugin
                }
            }
            _ => {
                // For other record types, continue to next plugin
                debug!("HOSTS: Ignoring non-A/AAAA query for {}", qname);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hosts_add() {
        let mut hosts = HostsPlugin::new();
        hosts.add_host("example.com".to_string(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        
        assert!(hosts.has_host("example.com"));
        assert!(hosts.has_host("example.com."));
        assert!(!hosts.has_host("other.com"));
    }

    #[test]
    fn test_hosts_file_loading() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Comment line").unwrap();
        writeln!(temp_file, "127.0.0.1 localhost localhost.localdomain").unwrap();
        writeln!(temp_file, "::1 localhost").unwrap();
        writeln!(temp_file, "192.168.1.1 router.local").unwrap();
        writeln!(temp_file, "").unwrap(); // Empty line
        writeln!(temp_file, "invalid line should be ignored").unwrap();
        temp_file.flush().unwrap();

        let hosts = HostsPlugin::load_from_file(temp_file.path().to_path_buf()).unwrap();
        
        assert!(hosts.has_host("localhost"));
        assert!(hosts.has_host("localhost.localdomain"));
        assert!(hosts.has_host("router.local"));
        
        let localhost_ips = hosts.get_ips("localhost").unwrap();
        assert!(localhost_ips.len() >= 2); // Both IPv4 and IPv6
    }

    #[tokio::test]
    async fn test_hosts_query() {
        let mut hosts = HostsPlugin::new();
        hosts.add_host("test.local".to_string(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        let mut message = Message::new();
        message.set_id(1234);
        let name = Name::from_str("test.local.").unwrap();
        let query = hickory_proto::op::Query::query(name, RecordType::A);
        message.add_query(query);

        let mut ctx = Context::new(message, "127.0.0.1:12345".parse().unwrap());
        
        hosts.handle(&mut ctx).await.unwrap();
        
        assert!(ctx.response.is_some());
        let response = ctx.response.unwrap();
        assert_eq!(response.answer_count(), 1);
    }
}
