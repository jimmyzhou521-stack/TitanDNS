// IP Matcher Plugin: CIDR List Matching for DNS Responses
// Loads IP CIDR rules from text files and matches response IPs against them

use anyhow::Result;
use ipnet::IpNet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// IpMatcherPlugin loads IP CIDR lists from files and matches DNS response IPs
#[derive(Debug, Clone)]
pub struct IpMatcherPlugin {
    pub name: String,
    cidrs: Vec<IpNet>,          // CIDR networks to match against
    mark: Option<String>,
    total_rules: usize,
}

impl IpMatcherPlugin {
    /// Create a new IpMatcherPlugin from a list of rule files
    pub fn new(name: String, files: Vec<String>, mark: Option<String>) -> Self {
        let mut cidrs = Vec::new();
        let mut total_rules = 0;

        for file_path in &files {
            match Self::load_file(file_path, &mut cidrs) {
                Ok(count) => {
                    total_rules += count;
                    info!("📂 IpMatcher '{}': Loaded {} CIDRs from {}", name, count, file_path);
                }
                Err(e) => {
                    warn!("⚠️ IpMatcher '{}': Failed to load {}: {}", name, file_path, e);
                }
            }
        }

        info!("✅ IpMatcher '{}': Total {} CIDR rules loaded", name, total_rules);

        Self {
            name,
            cidrs,
            mark,
            total_rules,
        }
    }

    /// Load CIDR rules from a single file
    fn load_file(path: &str, cidrs: &mut Vec<IpNet>) -> Result<usize> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(anyhow::anyhow!("File not found: {}", path.display()));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            // Parse CIDR notation
            match line.parse::<IpNet>() {
                Ok(net) => {
                    cidrs.push(net);
                    count += 1;
                }
                Err(_) => {
                    // Try parsing as single IP (convert to /32 or /128)
                    if let Ok(ip) = line.parse::<IpAddr>() {
                        let net = match ip {
                            IpAddr::V4(v4) => match IpNet::new(IpAddr::V4(v4), 32) {
                                Ok(n) => n,
                                Err(_) => continue, // Skip invalid IPv4 /32
                            },
                            IpAddr::V6(v6) => match IpNet::new(IpAddr::V6(v6), 128) {
                                Ok(n) => n,
                                Err(_) => continue, // Skip invalid IPv6 /128
                            },
                        };
                        cidrs.push(net);
                        count += 1;
                    }
                    // Skip invalid lines silently
                }
            }
        }

        Ok(count)
    }

    /// Check if an IP matches any CIDR in the list
    pub fn matches(&self, ip: IpAddr) -> bool {
        for cidr in &self.cidrs {
            if cidr.contains(&ip) {
                return true;
            }
        }
        false
    }

    /// Get total rule count
    pub fn rule_count(&self) -> usize {
        self.total_rules
    }
}

impl Plugin for IpMatcherPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // Only process if we have a response
        let response = match &ctx.response {
            Some(resp) => resp,
            None => return Ok(()),
        };

        // Check each answer record for A/AAAA
        for ans in response.answers() {
            let data = ans.data();
            
            let ip = if let Some(a) = data.as_a() {
                Some(IpAddr::V4(a.0))
            } else if let Some(aaaa) = data.as_aaaa() {
                Some(IpAddr::V6(aaaa.0))
            } else {
                None
            };

            if let Some(ip) = ip {
                if self.matches(ip) {
                    debug!("✅ IpMatcher '{}': IP {} matched CIDR list", self.name, ip);
                    
                    // Add tag if configured
                    if let Some(ref mark) = self.mark {
                        ctx.add_tag(mark);
                    }
                    
                    // Found a match, no need to check further
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip_match() {
        let mut cidrs = Vec::new();
        cidrs.push("1.0.1.0/24".parse().unwrap());
        cidrs.push("2001:db8::/32".parse().unwrap());

        let plugin = IpMatcherPlugin {
            name: "test".to_string(),
            cidrs,
            mark: Some("cn".to_string()),
            total_rules: 2,
        };

        // Should match
        assert!(plugin.matches(IpAddr::V4(Ipv4Addr::new(1, 0, 1, 100))));
        assert!(plugin.matches(IpAddr::V6("2001:db8::1".parse().unwrap())));

        // Should not match
        assert!(!plugin.matches(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!plugin.matches(IpAddr::V6("2001:4860::1".parse().unwrap())));
    }
}
