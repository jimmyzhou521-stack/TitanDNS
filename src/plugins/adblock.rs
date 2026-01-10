use crate::core::context::Context;
use crate::core::plugin::Plugin;
use anyhow::{Result};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};
use hickory_proto::op::{Message, ResponseCode, MessageType, OpCode};
use crate::stats::STATS;

#[derive(Clone, Debug)]
struct RuleSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

impl RuleSet {
    fn new() -> Self {
        Self {
            exact: HashSet::new(),
            suffix: HashSet::new(),
        }
    }

    fn insert(&mut self, pattern: &str) {
        let clean = pattern.trim();
        // Skip comments and cosmetic rules (element hiding) containing ##
        if clean.is_empty() || clean.starts_with('!') || clean.starts_with('[') || clean.contains("##") {
            return;
        }

        if let Some(domain) = clean.strip_prefix("||") {
            // Suffix rule: ||example.com^ -> example.com
            // Clean up trailing separators
            let domain = domain.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
            self.suffix.insert(domain.to_lowercase());
        } else {
            // Exact match or Hosts file style
            // Remove common IP prefixes if present
            let domain = if clean.starts_with("127.0.0.1 ") {
                clean.split_whitespace().nth(1).unwrap_or("")
            } else if clean.starts_with("0.0.0.0 ") {
                clean.split_whitespace().nth(1).unwrap_or("")
            } else {
                clean
            };
            self.exact.insert(domain.to_lowercase());
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // 1. Check Exact
        if self.exact.contains(&domain_lower) {
            return true;
        }

        // 2. Check Suffix (Iterative strip)
        // e.g. a.b.c -> check a.b.c, b.c, c
        let mut d = domain_lower.as_str();
        while !d.is_empty() {
             if self.suffix.contains(d) {
                 return true;
             }
             if let Some(pos) = d.find('.') {
                 d = &d[pos+1..];
             } else {
                 break;
             }
        }
        false
    }
}

#[derive(Clone, Debug)]
pub struct AdBlockPlugin {
    name: String,
    blacklist: Arc<RuleSet>,
    whitelist: Arc<RuleSet>,
}

impl AdBlockPlugin {
    pub fn new(name: String, files: Vec<String>) -> Result<Self> {
        let mut blacklist = RuleSet::new();
        let mut whitelist = RuleSet::new();
        let mut total_rules = 0;

        for path in files {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    for line in content.lines() {
                        let line = line.trim();
                        // Handle White/Black list logic from AdGuard syntax
                        // @@||example.com^ -> Whitelist
                        if line.starts_with("@@") {
                            whitelist.insert(&line[2..]);
                        } else {
                            blacklist.insert(line);
                        }
                        total_rules += 1;
                    }
                    info!("🛡️ AdBlock loaded file: {}", path);
                },
                Err(e) => {
                    warn!("⚠️ AdBlock failed to load rule file '{}': {}", path, e);
                }
            }
        }
        info!("🛡️ AdBlock initialized with total {} rules", total_rules);

        Ok(Self {
            name,
            blacklist: Arc::new(blacklist),
            whitelist: Arc::new(whitelist),
        })
    }
}

impl Plugin for AdBlockPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if ctx.response.is_some() {
            return Ok(());
        }

        if let Some(query) = ctx.request.query() {
            let should_block = {
                let hostname = ctx.qname_ref().trim_end_matches('.');
                // 1. Check Whitelist first
                if self.whitelist.matches(hostname) {
                    return Ok(());
                }
                // 2. Check Blacklist
                self.blacklist.matches(hostname)
            };

            if should_block {
                let hostname = ctx.qname_ref().trim_end_matches('.').to_string();
                info!("🚫 AdBlock Blocked: {}", hostname);
                STATS.record_blocked(&hostname);
                
                // Construct Block Response (NXDOMAIN)
                let mut response = Message::new();
                response.set_id(ctx.request.id());
                response.set_op_code(OpCode::Query);
                response.set_message_type(MessageType::Response);
                response.set_response_code(ResponseCode::NXDomain);
                response.set_recursion_available(true);
                response.add_query(query.clone());

                ctx.response = Some(response);
            }
        }

        Ok(())
    }
}
