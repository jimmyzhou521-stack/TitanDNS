//! GeoSite Plugin
//!
//! Based on Domain Trie for O(1) matching performance (resolves 100% CPU issues).
//! All rules are treated as Suffix/RootDomain rules to ensure maximum coverage (e.g. qq.com matches www.qq.com).

use anyhow::Result;
use moka::sync::Cache;
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::core::context::Context;
use crate::core::geosite_proto::{domain, GeoSiteList};
use crate::core::plugin::Plugin;
use prost::Message;

/// Trie Node
#[derive(Debug, Default, Clone)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    is_match: bool,
}

/// Domain Set (Trie + Plain)
#[derive(Debug, Clone)]
pub struct DomainSet {
    root: TrieNode,
    plain: Vec<String>,
    cache: Cache<String, bool>,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self {
            root: TrieNode::default(),
            plain: Vec::new(),
            cache: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }
}

impl DomainSet {
    fn add_plain(&mut self, plain: String) {
        self.plain.push(plain.to_lowercase());
    }

    /// Add domain to Trie (treated as Suffix)
    fn add_domain(&mut self, domain: String) {
        if domain.is_empty() {
            return;
        }

        let domain_lower = domain.to_lowercase();
        // Remove trailing dot if any
        let domain_clean = domain_lower.trim_end_matches('.');

        let mut node = &mut self.root;
        // Split by dot and reverse: "www.qq.com" -> ["com", "qq", "www"]
        for part in domain_clean.rsplit('.') {
            if part.is_empty() {
                continue;
            }
            node = node.children.entry(part.to_string()).or_default();
        }
        node.is_match = true;
    }

    fn normalize_domain<'a>(domain: &'a str) -> Cow<'a, str> {
        let d = domain.trim_end_matches('.');
        let has_upper = d.as_bytes().iter().any(|b| b.is_ascii_uppercase());
        if has_upper {
            Cow::Owned(d.to_ascii_lowercase())
        } else {
            Cow::Borrowed(d)
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = Self::normalize_domain(domain);
        let domain_clean = domain.as_ref();

        if let Some(cached) = self.cache.get(domain_clean) {
            return cached;
        }

        // 1. Trie Match (Suffix)
        let mut node = &self.root;
        for part in domain_clean.rsplit('.') {
            if let Some(child) = node.children.get(part) {
                node = child;
                // If this node is a match, then the suffix matches
                // e.g. Query "www.qq.com". Tree has "com"->"qq"(match).
                // "com" -> found. "qq" -> found & is_match -> Return TRUE.
                if node.is_match {
                    let key = match domain {
                        Cow::Borrowed(d) => d.to_string(),
                        Cow::Owned(s) => s,
                    };
                    self.cache.insert(key, true);
                    return true;
                }
            } else {
                // Path divergence, no match in this branch
                break;
            }
        }

        // 2. Plain Match (Fallback, mainly for keywords)
        for p in &self.plain {
            if domain_clean.contains(p) {
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

    fn matches_lower_with_parts(&self, domain_lower: &str, ranges: &[(usize, usize)]) -> bool {
        let domain_clean = domain_lower.trim_end_matches('.');

        if let Some(cached) = self.cache.get(domain_clean) {
            return cached;
        }

        // 1. Trie Match (Suffix) using precomputed ranges
        let mut node = &self.root;
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

        // 2. Plain Match (Fallback, mainly for keywords)
        for p in &self.plain {
            if domain_clean.contains(p) {
                self.cache.insert(domain_clean.to_string(), true);
                return true;
            }
        }

        self.cache.insert(domain_clean.to_string(), false);
        false
    }
}

/// GeoSite Plugin
#[derive(Clone)]
pub struct GeoSitePlugin {
    pub name: String,
    pub categories: Arc<RwLock<HashMap<String, DomainSet>>>,
    pub target_category: String,
    pub mark: Option<String>,
}

impl std::fmt::Debug for GeoSitePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoSitePlugin")
            .field("name", &self.name)
            .field("categories_count", &self.categories.read().len())
            .field("target_category", &self.target_category)
            .field("mark", &self.mark)
            .finish()
    }
}

impl GeoSitePlugin {
    pub fn new(target_category: impl Into<String>) -> Self {
        Self {
            name: "geosite".to_string(),
            categories: Arc::new(RwLock::new(HashMap::new())),
            target_category: target_category.into().to_lowercase(),
            mark: None,
        }
    }

    pub fn with_mark(mut self, mark: impl Into<String>) -> Self {
        self.mark = Some(mark.into());
        self
    }

    pub fn add_domain(
        &self,
        category: impl Into<String>,
        domain: impl Into<String>,
        r#type: domain::Type,
    ) {
        let category = category.into().to_lowercase();
        let domain = domain.into();

        let mut categories = self.categories.write();
        let set = categories
            .entry(category)
            .or_insert_with(DomainSet::default);

        match r#type {
            domain::Type::Plain => set.add_plain(domain),
            // Treat all others as Suffix (Trie) for performance and coverage
            _ => set.add_domain(domain),
        }
    }

    pub fn load_from_file(&self, path: impl Into<String>) -> Result<()> {
        let path_str = path.into();

        if let Some((file_path, tag)) = path_str.split_once(':') {
            let path_buf = PathBuf::from(file_path);
            let ext = path_buf.extension().and_then(|s| s.to_str()).unwrap_or("");

            if ext == "dat" {
                return self.load_binary_category(&path_buf, tag);
            } else {
                return self.load_text(&path_buf);
            }
        }

        let path_buf = PathBuf::from(&path_str);
        let ext = path_buf.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext == "dat" {
            self.load_binary(&path_buf)
        } else {
            self.load_text(&path_buf)
        }
    }

    fn load_binary_category(&self, path: &PathBuf, target_tag: &str) -> Result<()> {
        let data = fs::read(path)?;
        let list = GeoSiteList::decode(&data[..])?;

        let target = target_tag.to_lowercase();
        let mut count = 0;

        for entry in list.entry {
            let code = entry.country_code.to_lowercase();
            if code == target {
                for d in entry.domain {
                    // Map types to implementation types
                    let r#type = match d.r#type {
                        0 => domain::Type::Plain,
                        _ => domain::Type::RootDomain, // Treat Full/Regex/Domain as Suffix
                    };
                    self.add_domain(&self.target_category, d.value, r#type); // 🔧 Fix: 存储到 target_category，不是 source category
                    count += 1;
                }
            }
        }

        if count > 0 {
            info!(
                "📂 GeoSite (Trie): Loaded {} domains for category '{}' from {:?}",
                count, self.target_category, path
            );
        } else {
            warn!(
                "⚠️  GeoSite: Category '{}' NOT FOUND in {:?}",
                target_tag, path
            );
        }
        Ok(())
    }

    fn load_binary(&self, path: &PathBuf) -> Result<()> {
        let data = fs::read(path)?;
        let list = GeoSiteList::decode(&data[..])?;

        let target = self.target_category.as_str();
        let mut count = 0;

        for entry in list.entry {
            let code = entry.country_code.to_lowercase();
            if code == target {
                for d in entry.domain {
                    let r#type = match d.r#type {
                        0 => domain::Type::Plain,
                        _ => domain::Type::RootDomain,
                    };
                    self.add_domain(&self.target_category, d.value, r#type); // 🔧 Fix: 存储到 target_category
                    count += 1;
                }
            }
        }

        info!(
            "📂 GeoSite (Trie): Loaded {} domains for category '{}' from {:?}",
            count, self.target_category, path
        );
        Ok(())
    }

    fn load_text(&self, path: &PathBuf) -> Result<()> {
        let content = fs::read_to_string(path)?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((category, domain)) = line.split_once(':') {
                self.add_domain(category.trim(), domain.trim(), domain::Type::RootDomain);
            } else {
                self.add_domain(&self.target_category, line.trim(), domain::Type::RootDomain);
            }
        }

        info!("📂 GeoSite (Text Trie): Loaded rules from {:?}", path);
        Ok(())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let categories = self.categories.read();
        let target = &self.target_category;

        if let Some(set) = categories.get(target) {
            set.matches(domain)
        } else {
            false
        }
    }

    pub fn matches_with_parts(&self, domain_lower: &str, ranges: &[(usize, usize)]) -> bool {
        let categories = self.categories.read();
        let target = &self.target_category;

        if let Some(set) = categories.get(target) {
            set.matches_lower_with_parts(domain_lower, ranges)
        } else {
            false
        }
    }
}

impl Plugin for GeoSitePlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if ctx.request.queries().first().is_some() {
            let matched = {
                let domain_lower = ctx.qname_lower_ref();
                let ranges = ctx.qname_parts_ranges();
                self.matches_with_parts(domain_lower, ranges)
            };

            if matched {
                // tracing::info!("🌍 GeoMatch [{}]: {}", self.target_category, ctx.qname_ref());

                if let Some(mark) = &self.mark {
                    ctx.add_tag(mark);
                    tracing::debug!("✅ Added tag '{}' to context", mark);
                }
            }
        }
        Ok(())
    }
}
