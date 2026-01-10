// Matcher Plugin: Domain List Matching
// Loads domain rules from text files and matches queries against them

use anyhow::Result;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use radix_trie::{Trie, TrieCommon};
use moka::sync::Cache;
use tracing::{debug, info, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// MatcherPlugin loads domain lists from files and matches queries
#[derive(Debug)]
pub struct MatcherPlugin {
    pub name: String,
    domains: HashSet<String>,     // Exact domain matches
    suffix_trie: Trie<String, ()>, // Suffix matches (reversed domain trie)
    mark: Option<String>,
    cache: Cache<String, bool>,
    total_rules: usize,
}

impl MatcherPlugin {
    /// Create a new MatcherPlugin from a list of rule files
    pub fn new(name: String, files: Vec<String>, mark: Option<String>) -> Self {
        let mut domains = HashSet::new();
        let mut suffix_trie = Trie::new();
        let mut total_rules = 0;
        let cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(3600))
            .build();

        for file_path in &files {
            match Self::load_file(file_path, &mut domains, &mut suffix_trie) {
                Ok(count) => {
                    total_rules += count;
                    info!("📂 Matcher '{}': Loaded {} rules from {}", name, count, file_path);
                }
                Err(e) => {
                    warn!("⚠️ Matcher '{}': Failed to load {}: {}", name, file_path, e);
                }
            }
        }

        info!("✅ Matcher '{}': Total {} rules loaded", name, total_rules);

        Self {
            name,
            domains,
            suffix_trie,
            mark,
            total_rules,
            cache,
        }
    }

    /// Load rules from a single file
    fn load_file(
        path: &str,
        domains: &mut HashSet<String>,
        suffix_trie: &mut Trie<String, ()>,
    ) -> Result<usize> {
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

            // Parse different rule formats
            let domain = Self::parse_rule(line);
            if let Some(d) = domain {
                if d.starts_with('.') {
                    // Suffix match (e.g., ".example.com" matches "sub.example.com")
                    // Store reversed suffix (keeps leading dot for boundary safety)
                    let rev = Self::reverse_domain(&d);
                    suffix_trie.insert(rev, ());

                    // Also allow exact match on base domain ("example.com")
                    if let Some(base) = d.strip_prefix('.') {
                        if !base.is_empty() {
                            domains.insert(base.to_string());
                        }
                    }
                } else {
                    // Exact match
                    domains.insert(d);
                }
                count += 1;
            }
        }

        Ok(count)
    }

    /// Parse a single rule line into a domain
    fn parse_rule(line: &str) -> Option<String> {
        let line = line.to_lowercase();

        // Handle different formats:
        // 1. Plain domain: example.com
        // 2. With prefix: domain:example.com
        // 3. With suffix: full:example.com
        // 4. Keyword: keyword:xxx (skip for now)
        // 5. Regex: regexp:xxx (skip for now)

        if line.starts_with("keyword:") || line.starts_with("regexp:") {
            // Skip keyword and regex rules for now
            return None;
        }

        let domain = if line.starts_with("domain:") {
            line.strip_prefix("domain:")?.to_string()
        } else if line.starts_with("full:") {
            line.strip_prefix("full:")?.to_string()
        } else if line.starts_with("suffix:") {
            format!(".{}", line.strip_prefix("suffix:")?)
        } else if line.contains(':') {
            // Unknown prefix, skip
            return None;
        } else {
            // Plain domain
            line.to_string()
        };

        // Clean up trailing dot
        let domain = domain.trim_end_matches('.').to_string();

        if domain.is_empty() {
            return None;
        }

        Some(domain)
    }

    /// Normalize domain for matching (trim trailing dot, lower-case if needed)
    fn normalize_domain<'a>(domain: &'a str) -> Cow<'a, str> {
        let d = domain.trim_end_matches('.');
        let has_upper = d.as_bytes().iter().any(|b| b.is_ascii_uppercase());
        if has_upper {
            Cow::Owned(d.to_ascii_lowercase())
        } else {
            Cow::Borrowed(d)
        }
    }

    /// Reverse a domain for suffix trie matching
    fn reverse_domain(domain: &str) -> String {
        let mut rev = String::with_capacity(domain.len());
        for b in domain.as_bytes().iter().rev() {
            rev.push(*b as char);
        }
        rev
    }

    /// Check if a domain matches any rule
    pub fn matches(&self, domain: &str) -> bool {
        let domain = Self::normalize_domain(domain);
        let domain_ref = domain.as_ref();

        if let Some(cached) = self.cache.get(domain_ref) {
            return cached;
        }

        // Exact match
        if self.domains.contains(domain_ref) {
            let key = match domain {
                Cow::Borrowed(d) => d.to_string(),
                Cow::Owned(s) => s,
            };
            self.cache.insert(key, true);
            return true;
        }

        // Suffix match via radix trie (reversed domain prefix)
        if !self.suffix_trie.is_empty() {
            let rev = Self::reverse_domain(domain_ref);
            if self.suffix_trie.get_ancestor_value(&rev).is_some() {
                let key = match domain {
                    Cow::Borrowed(d) => d.to_string(),
                    Cow::Owned(s) => s,
                };
                self.cache.insert(key, true);
                return true;
            }
        }

        let key = match domain {
            Cow::Borrowed(d) => d.to_string(),
            Cow::Owned(s) => s,
        };
        self.cache.insert(key, false);
        false
    }

    /// Get total rule count
    pub fn rule_count(&self) -> usize {
        self.total_rules
    }
}

impl Plugin for MatcherPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if ctx.request.query().is_none() {
            return Ok(());
        }

        let domain = ctx.qname_ref();

        if self.matches(domain) {
            debug!("✅ Matcher '{}' matched: {}", self.name, domain);
            
            // Add tag if configured
            if let Some(ref mark) = self.mark {
                ctx.add_tag(mark);
            }
        }

        Ok(())
    }
}

impl Clone for MatcherPlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            domains: self.domains.clone(),
            suffix_trie: self.suffix_trie.clone(),
            mark: self.mark.clone(),
            total_rules: self.total_rules,
            cache: self.cache.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule() {
        assert_eq!(MatcherPlugin::parse_rule("example.com"), Some("example.com".to_string()));
        assert_eq!(MatcherPlugin::parse_rule("domain:example.com"), Some("example.com".to_string()));
        assert_eq!(MatcherPlugin::parse_rule("full:example.com"), Some("example.com".to_string()));
        assert_eq!(MatcherPlugin::parse_rule("suffix:example.com"), Some(".example.com".to_string()));
        assert_eq!(MatcherPlugin::parse_rule("keyword:xxx"), None);
        assert_eq!(MatcherPlugin::parse_rule("regexp:xxx"), None);
    }
}
