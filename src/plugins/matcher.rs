// Matcher Plugin: Domain List Matching
// Loads domain rules from text files and matches queries against them

use anyhow::Result;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use moka::sync::Cache;
use tracing::{debug, info, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// MatcherPlugin loads domain lists from files and matches queries
#[derive(Debug)]
pub struct MatcherPlugin {
    pub name: String,
    domains: HashSet<Arc<str>>,     // Exact domain matches (interned)
    suffix_root: SuffixNode,         // Suffix matches (label trie)
    keywords: HashSet<Arc<str>>,     // Keyword contains matches (interned)
    mark: Option<String>,
    cache: Cache<String, bool>,
    total_rules: usize,
}

#[derive(Debug, Default, Clone)]
struct SuffixNode {
    children: HashMap<Arc<str>, SuffixNode>,
    is_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Exact,
    Suffix,
    Keyword,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedRule {
    kind: RuleKind,
    value: String,
}

impl MatcherPlugin {
    /// Create a new MatcherPlugin from a list of rule files
    pub fn new(name: String, files: Vec<String>, mark: Option<String>) -> Self {
        let mut domains = HashSet::new();
        let mut suffix_root = SuffixNode::default();
        let mut keywords = HashSet::new();
        let mut total_rules = 0;
        let mut interner: HashSet<Arc<str>> = HashSet::new();
        let cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(3600))
            .build();

        for file_path in &files {
            match Self::load_file(file_path, &mut domains, &mut suffix_root, &mut keywords, &mut interner) {
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
            suffix_root,
            keywords,
            mark,
            total_rules,
            cache,
        }
    }

    /// Load rules from a single file
    fn load_file(
        path: &str,
        domains: &mut HashSet<Arc<str>>,
        suffix_root: &mut SuffixNode,
        keywords: &mut HashSet<Arc<str>>,
        interner: &mut HashSet<Arc<str>>,
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
            let rule = Self::parse_rule(line);
            if let Some(rule) = rule {
                match rule.kind {
                    RuleKind::Suffix => {
                        // Suffix match (e.g., "example.com" matches "sub.example.com")
                        // Store as label trie: "www.example.com" -> com -> example
                        let clean = rule.value.trim_start_matches('.').trim_end_matches('.');
                        if !clean.is_empty() {
                            let mut node = &mut *suffix_root;
                            for part in clean.rsplit('.') {
                                if part.is_empty() {
                                    continue;
                                }
                                let key = Self::intern_label(interner, part);
                                node = node.children.entry(key).or_default();
                            }
                            node.is_match = true;

                            // Also allow exact match on base domain ("example.com")
                            let key = Self::intern_label(interner, clean);
                            domains.insert(key);
                        }
                    }
                    RuleKind::Exact => {
                        let key = Self::intern_label(interner, &rule.value);
                        domains.insert(key);
                    }
                    RuleKind::Keyword => {
                        let key = Self::intern_label(interner, &rule.value);
                        keywords.insert(key);
                    }
                }
                count += 1;
            }
        }

        Ok(count)
    }

    fn intern_label(interner: &mut HashSet<Arc<str>>, label: &str) -> Arc<str> {
        if let Some(existing) = interner.get(label) {
            return existing.clone();
        }
        let arc: Arc<str> = Arc::from(label);
        interner.insert(arc.clone());
        arc
    }

    /// Parse a single rule line into a parsed rule
    fn parse_rule(line: &str) -> Option<ParsedRule> {
        let line = line.to_lowercase();

        // Handle different formats:
        // 1. Plain domain: example.com
        // 2. With prefix: domain:example.com
        // 3. With suffix: suffix:example.com
        // 4. Keyword: keyword:xxx
        // 5. Regex: regexp:xxx (skip)

        if line.starts_with("regexp:") {
            return None;
        }

        let (mut kind, mut value) = if line.starts_with("keyword:") {
            (RuleKind::Keyword, line.strip_prefix("keyword:")?.to_string())
        } else if line.starts_with("domain:") {
            (RuleKind::Exact, line.strip_prefix("domain:")?.to_string())
        } else if line.starts_with("full:") {
            (RuleKind::Exact, line.strip_prefix("full:")?.to_string())
        } else if line.starts_with("suffix:") {
            (RuleKind::Suffix, line.strip_prefix("suffix:")?.to_string())
        } else if line.contains(':') {
            // Unknown prefix, skip
            return None;
        } else {
            // Plain domain
            (RuleKind::Exact, line.to_string())
        };

        value = value.trim().trim_end_matches('.').to_string();
        if value.is_empty() {
            return None;
        }

        if kind != RuleKind::Keyword && value.starts_with('.') {
            kind = RuleKind::Suffix;
            value = value.trim_start_matches('.').to_string();
        }

        if kind == RuleKind::Suffix {
            value = value.trim_start_matches('.').to_string();
            if value.is_empty() {
                return None;
            }
        }

        Some(ParsedRule { kind, value })
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

    #[inline]
    fn clean_domain<'a>(domain_lower: &'a str) -> &'a str {
        if domain_lower.as_bytes().last() == Some(&b'.') {
            &domain_lower[..domain_lower.len() - 1]
        } else {
            domain_lower
        }
    }

    /// Check if a domain matches any rule
    pub fn matches(&self, domain: &str) -> bool {
        let domain = Self::normalize_domain(domain);
        let domain_ref = domain.as_ref();
        self.matches_lower(domain_ref)
    }

    fn matches_lower(&self, domain_lower: &str) -> bool {
        let domain_clean = Self::clean_domain(domain_lower);

        if let Some(cached) = self.cache.get(domain_clean) {
            return cached;
        }

        // Exact match
        if self.domains.contains(domain_clean) {
            self.cache.insert(domain_clean.to_string(), true);
            return true;
        }

        // Suffix match via label trie
        let mut node = &self.suffix_root;
        for part in domain_clean.rsplit('.') {
            if let Some(child) = node.children.get(part) {
                node = child;
                if node.is_match {
                    self.cache.insert(domain_clean.to_string(), true);
                    return true;
                }
            } else {
                break;
            }
        }

        // Keyword contains match
        if !self.keywords.is_empty() {
            for keyword in &self.keywords {
                if domain_clean.contains(keyword.as_ref()) {
                    self.cache.insert(domain_clean.to_string(), true);
                    return true;
                }
            }
        }

        self.cache.insert(domain_clean.to_string(), false);
        false
    }

    fn matches_lower_with_parts(&self, domain_lower: &str, ranges: &[(usize, usize)]) -> bool {
        let domain_clean = Self::clean_domain(domain_lower);

        if let Some(cached) = self.cache.get(domain_clean) {
            return cached;
        }

        // Exact match
        if self.domains.contains(domain_clean) {
            self.cache.insert(domain_clean.to_string(), true);
            return true;
        }

        // Suffix match via label trie using precomputed ranges
        let mut node = &self.suffix_root;
        for (start, end) in ranges.iter().rev() {
            if *end > domain_clean.len() {
                continue;
            }
            let part = &domain_clean[*start..*end];
            if let Some(child) = node.children.get(part) {
                node = child;
                if node.is_match {
                    self.cache.insert(domain_clean.to_string(), true);
                    return true;
                }
            } else {
                break;
            }
        }

        // Keyword contains match
        if !self.keywords.is_empty() {
            for keyword in &self.keywords {
                if domain_clean.contains(keyword.as_ref()) {
                    self.cache.insert(domain_clean.to_string(), true);
                    return true;
                }
            }
        }

        self.cache.insert(domain_clean.to_string(), false);
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
        let domain_lower = ctx.qname_lower_ref();
        let ranges = ctx.qname_parts_ranges();

        if self.matches_lower_with_parts(domain_lower, ranges) {
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
            suffix_root: self.suffix_root.clone(),
            keywords: self.keywords.clone(),
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
        assert_eq!(
            MatcherPlugin::parse_rule("example.com"),
            Some(ParsedRule { kind: RuleKind::Exact, value: "example.com".to_string() })
        );
        assert_eq!(
            MatcherPlugin::parse_rule("domain:example.com"),
            Some(ParsedRule { kind: RuleKind::Exact, value: "example.com".to_string() })
        );
        assert_eq!(
            MatcherPlugin::parse_rule("full:example.com"),
            Some(ParsedRule { kind: RuleKind::Exact, value: "example.com".to_string() })
        );
        assert_eq!(
            MatcherPlugin::parse_rule("suffix:example.com"),
            Some(ParsedRule { kind: RuleKind::Suffix, value: "example.com".to_string() })
        );
        assert_eq!(
            MatcherPlugin::parse_rule(".example.com"),
            Some(ParsedRule { kind: RuleKind::Suffix, value: "example.com".to_string() })
        );
        assert_eq!(
            MatcherPlugin::parse_rule("keyword:xxx"),
            Some(ParsedRule { kind: RuleKind::Keyword, value: "xxx".to_string() })
        );
        assert_eq!(MatcherPlugin::parse_rule("regexp:xxx"), None);
    }
}
