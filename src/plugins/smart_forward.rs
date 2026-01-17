use crate::config::UpstreamConfig;
use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::plugins::forward::{ForwardPlugin, ForwardTuning, Upstream};
use crate::plugins::geoip::GeoIpPlugin;
use crate::plugins::ip_matcher::IpMatcherPlugin;
use crate::stats::STATS;
use anyhow::{bail, Context as AnyhowContext, Result};
use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use moka::future::Cache;
use moka::sync::Cache as SyncCache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// SmartForwardPlugin
/// "The Ultimate Splitter" with Auto-Learning + Persistence
/// Logic:
/// 1. Check Learning Cache: If we already know this domain is CN/Global, route directly.
/// 2. If unknown: Query Local Upstream (Probe).
/// 3. Check IP Matcher (txt lists, <1μs) -> GeoIP (mmdb, 10-50μs fallback) of real IP.
/// 4. If CN -> Return Real IP AND Cache as CN.
/// 5. If Foreign -> Query FakeIP Upstream -> Return FakeIP AND Cache as Global.
/// 6. [NEW] Persist learning cache to disk for survival across restarts.
#[derive(Debug)]
pub struct SmartForwardPlugin {
    pub name: String,
    pub local: SmartForwardTarget,
    pub fakeip: SmartForwardTarget,
    pub local_fallback: Option<SmartForwardTarget>,
    local_label: String,
    fake_label: String,
    local_fallback_label: Option<String>,
    pub avoid_fakeip_on_domestic: bool,
    pub prefer_local_on_miss: bool,
    pub domestic_suffixes: Vec<String>,
    pub domestic_suffix_labels: Vec<Vec<String>>,
    pub ip_matcher: Option<Arc<IpMatcherPlugin>>, // 高精度IP列表（优先，<1μs）
    pub geoip: Arc<GeoIpPlugin>,                  // GeoIP数据库（兜底，10-50μs）
    pub default_timeout: Duration,
    // Auto-Learning Cache: Domain -> is_cn (true=CN, false=Global)
    pub learning_cache: Cache<String, bool>,
    // Fast domain classification cache (short TTL, lock-free)
    pub domain_cache: Arc<DashMap<String, (bool, u64)>>,
    // Async learning update channel (reduces hot-path lock contention)
    pub learning_tx: mpsc::Sender<(String, bool)>,
    // IP classification cache (LRU/TTL to skip repeated GeoIP/IPMatcher)
    pub ip_class_cache: SyncCache<IpAddr, bool>,
    // [NEW] Persistence file path (None = memory only)
    pub persist_file: Option<PathBuf>,
    // [NEW] Shadow copy for persistence (moka doesn't support iteration)
    pub persist_data: Arc<DashMap<String, bool>>,
    persist_max_entries: usize,
}

const LEARNING_CACHE_MAX_ENTRIES_DEFAULT: usize = 10_000;
const LEARNING_CACHE_TTL_SECS_DEFAULT: u64 = 3600;
const DOMAIN_CLASS_CACHE_TTL_SECS: u64 = 900; // 15 minutes
const IP_CLASS_CACHE_TTL_SECS: u64 = 3600; // 60 minutes

#[derive(Debug)]
pub enum SmartForwardTarget {
    Single {
        upstream: Arc<Upstream>,
        label: String,
        timeout: Duration,
    },
    Group {
        forward: Arc<ForwardPlugin>,
        label: String,
    },
}

impl SmartForwardTarget {
    fn label(&self) -> &str {
        match self {
            SmartForwardTarget::Single { label, .. } => label,
            SmartForwardTarget::Group { label, .. } => label,
        }
    }

    fn matches_label(&self, label: &str) -> bool {
        if self.label() == label {
            return true;
        }
        match self {
            SmartForwardTarget::Group { forward, .. } => {
                forward.upstreams.iter().any(|u| u.get_label() == label)
            }
            SmartForwardTarget::Single { .. } => false,
        }
    }
}

impl SmartForwardPlugin {
    pub async fn new(
        name: String,
        local_conf: Option<UpstreamConfig>,
        fakeip_conf: Option<UpstreamConfig>,
        local_upstreams: Vec<UpstreamConfig>,
        fakeip_upstreams: Vec<UpstreamConfig>,
        local_strategy: Option<String>,
        fakeip_strategy: Option<String>,
        local_concurrent: Option<usize>,
        fakeip_concurrent: Option<usize>,
        local_timeout_ms: Option<u64>,
        fakeip_timeout_ms: Option<u64>,
        local_fallback_upstreams: Vec<UpstreamConfig>,
        local_fallback_strategy: Option<String>,
        local_fallback_concurrent: Option<usize>,
        local_fallback_timeout_ms: Option<u64>,
        avoid_fakeip_on_domestic: bool,
        prefer_local_on_miss: bool,
        domestic_suffixes: Vec<String>,
        ip_matcher: Option<Arc<IpMatcherPlugin>>,
        geoip: Arc<GeoIpPlugin>,
        learning_cache_file: Option<String>, // [NEW] Persistence file
        learning_cache_max_entries: Option<usize>,
        learning_cache_ttl_secs: Option<u64>,
        forward_tuning: ForwardTuning,
    ) -> Result<Self> {
        let local_timeout_ms = match local_timeout_ms {
            Some(v) if v > 0 => v,
            Some(_) => bail!("SmartForward '{}' local_timeout_ms must be > 0", name),
            None => bail!("SmartForward '{}' requires local_timeout_ms", name),
        };
        let fakeip_timeout_ms = match fakeip_timeout_ms {
            Some(v) if v > 0 => v,
            Some(_) => bail!("SmartForward '{}' fakeip_timeout_ms must be > 0", name),
            None => bail!("SmartForward '{}' requires fakeip_timeout_ms", name),
        };
        let local_fallback_timeout_ms = if !local_fallback_upstreams.is_empty() {
            match local_fallback_timeout_ms {
                Some(v) if v > 0 => Some(v),
                Some(_) => bail!("SmartForward '{}' local_fallback_timeout_ms must be > 0", name),
                None => bail!(
                    "SmartForward '{}' requires local_fallback_timeout_ms",
                    name
                ),
            }
        } else {
            None
        };

        let local_target = if !local_upstreams.is_empty() {
            let strategy = local_strategy.unwrap_or_else(|| "smart".to_string());
            let fp = ForwardPlugin::new(
                format!("{}::local", name),
                local_upstreams,
                Some(strategy),
                local_concurrent.unwrap_or(2),
                local_timeout_ms,
                forward_tuning.clone(),
            );
            // timeout 已在构造函数中设置
            let label = format!("{}:local", name);
            crate::autopilot::register_upstream(&label);
            SmartForwardTarget::Group {
                forward: Arc::new(fp),
                label,
            }
        } else {
            let conf = local_conf.context("SmartForward local is missing")?;
            let upstream =
                Upstream::new(conf, &forward_tuning).context("Failed to create local upstream")?;
            let label = upstream.get_label();
            crate::autopilot::register_upstream(&label);
            SmartForwardTarget::Single {
                upstream: Arc::new(upstream),
                label,
                timeout: Duration::from_millis(local_timeout_ms),
            }
        };

        let fake_target = if !fakeip_upstreams.is_empty() {
            let strategy = fakeip_strategy.unwrap_or_else(|| "smart".to_string());
            let fp = ForwardPlugin::new(
                format!("{}::fake", name),
                fakeip_upstreams,
                Some(strategy),
                fakeip_concurrent.unwrap_or(2),
                fakeip_timeout_ms,
                forward_tuning.clone(),
            );
            // timeout 已在构造函数中设置
            let label = format!("{}:fake", name);
            crate::autopilot::register_upstream(&label);
            SmartForwardTarget::Group {
                forward: Arc::new(fp),
                label,
            }
        } else {
            let conf = fakeip_conf.context("SmartForward fakeip is missing")?;
            let upstream =
                Upstream::new(conf, &forward_tuning).context("Failed to create fakeip upstream")?;
            let label = upstream.get_label();
            crate::autopilot::register_upstream(&label);
            SmartForwardTarget::Single {
                upstream: Arc::new(upstream),
                label,
                timeout: Duration::from_millis(fakeip_timeout_ms),
            }
        };

        let fallback_target = if !local_fallback_upstreams.is_empty() {
            let strategy = local_fallback_strategy.unwrap_or_else(|| "race".to_string());
            let fp = ForwardPlugin::new(
                format!("{}::local_fallback", name),
                local_fallback_upstreams,
                Some(strategy),
                local_fallback_concurrent.unwrap_or(2),
                local_fallback_timeout_ms.unwrap_or(0),
                forward_tuning.clone(),
            );
            // timeout 已在构造函数中设置
            let label = format!("{}:local_fallback", name);
            crate::autopilot::register_upstream(&label);
            Some(SmartForwardTarget::Group {
                forward: Arc::new(fp),
                label,
            })
        } else {
            None
        };

        let cache_max_entries =
            learning_cache_max_entries.unwrap_or(LEARNING_CACHE_MAX_ENTRIES_DEFAULT);
        if cache_max_entries == 0 {
            bail!(
                "SmartForward '{}' learning_cache_max_entries must be > 0",
                name
            );
        }
        let cache_ttl_secs = learning_cache_ttl_secs.unwrap_or(LEARNING_CACHE_TTL_SECS_DEFAULT);
        if cache_ttl_secs == 0 {
            bail!(
                "SmartForward '{}' learning_cache_ttl_secs must be > 0",
                name
            );
        }
        let persist_max_entries = cache_max_entries;

        // Cache learning results
        let cache = Cache::builder()
            .max_capacity(cache_max_entries as u64)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .build();

        // Fast classification cache (short TTL)
        let domain_cache: Arc<DashMap<String, (bool, u64)>> = Arc::new(DashMap::new());

        let ip_class_cache: SyncCache<IpAddr, bool> = SyncCache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(IP_CLASS_CACHE_TTL_SECS))
            .build();

        // [NEW] Initialize persist_data shadow copy
        let persist_data: DashMap<String, bool> = DashMap::new();
        let persist_data = Arc::new(persist_data);

        let persist_enabled = learning_cache_file.is_some();

        // Async learning updater (hot-path friendly)
        let (learning_tx, mut learning_rx) = mpsc::channel::<(String, bool)>(4096);
        {
            let cache_clone = cache.clone();
            let persist_clone = persist_data.clone();
            let domain_cache_clone = domain_cache.clone();
            tokio::spawn(async move {
                while let Some((domain, is_cn)) = learning_rx.recv().await {
                    cache_clone.insert(domain.clone(), is_cn).await;
                    if persist_enabled {
                        persist_clone.insert(domain.clone(), is_cn);
                        Self::trim_persist_data(persist_clone.as_ref(), persist_max_entries);
                    }
                    let expires_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_add(DOMAIN_CLASS_CACHE_TTL_SECS);
                    domain_cache_clone.insert(domain, (is_cn, expires_at));
                }
            });
        }

        // [NEW] Load persisted learning data if file exists
        let persist_path = learning_cache_file.map(PathBuf::from);
        if let Some(ref path) = persist_path {
            if path.exists() {
                match Self::load_learning_cache_from_file(path) {
                    Ok(data) => {
                        let count = data.len();
                        let max_entries = persist_max_entries;
                        let mut inserted = 0usize;
                        // Load into both cache and persist_data
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for (domain, is_cn) in data {
                            if inserted >= max_entries {
                                break;
                            }
                            let domain = crate::autopilot::normalize_domain_lower(&domain);
                            let domain_clean = domain.as_ref().trim_end_matches('.');
                            if domain_clean.is_empty() {
                                continue;
                            }
                            let domain_owned = domain_clean.to_string();
                            cache.insert(domain_owned.clone(), is_cn).await;
                            persist_data.insert(domain_owned.clone(), is_cn);
                            domain_cache.insert(
                                domain_owned,
                                (is_cn, now.saturating_add(DOMAIN_CLASS_CACHE_TTL_SECS)),
                            );
                            inserted += 1;
                        }
                        info!(
                            "📂 SmartForward '{}': Loaded {} learning entries from {:?}",
                            name, count, path
                        );
                        if count > max_entries {
                            warn!(
                                "⚠️ SmartForward '{}': Learning cache has {} entries, truncated to {}",
                                name, count, max_entries
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "⚠️ SmartForward '{}': Failed to load learning cache: {}",
                            name, e
                        );
                    }
                }
            } else {
                info!(
                    "📂 SmartForward '{}': Persistence file {:?} not found, starting fresh",
                    name, path
                );
            }
        }

        let domestic_suffixes: Vec<String> = domestic_suffixes
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();
        let mut domestic_suffix_labels: Vec<Vec<String>> = Vec::new();
        for suffix in &domestic_suffixes {
            let clean = suffix.trim_start_matches('.').trim_end_matches('.');
            if clean.is_empty() {
                continue;
            }
            let parts: Vec<String> = clean
                .split('.')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string())
                .collect();
            if !parts.is_empty() {
                domestic_suffix_labels.push(parts);
            }
        }

        let local_label = local_target.label().to_string();
        let fake_label = fake_target.label().to_string();
        let local_fallback_label = fallback_target.as_ref().map(|t| t.label().to_string());
        let default_timeout = Duration::from_millis(local_timeout_ms);

        Ok(Self {
            name,
            local: local_target,
            fakeip: fake_target,
            local_fallback: fallback_target,
            local_label,
            fake_label,
            local_fallback_label,
            avoid_fakeip_on_domestic,
            prefer_local_on_miss,
            domestic_suffixes,
            domestic_suffix_labels,
            ip_matcher,
            geoip,
            default_timeout,
            learning_cache: cache,
            domain_cache,
            learning_tx,
            ip_class_cache,
            persist_file: persist_path,
            persist_data,
            persist_max_entries,
        })
    }

    /// Load learning cache from JSON file
    fn load_learning_cache_from_file(path: &PathBuf) -> Result<HashMap<String, bool>> {
        let content = std::fs::read_to_string(path)?;
        let data: HashMap<String, bool> = serde_json::from_str(&content)?;
        Ok(data)
    }

    /// Save learning cache to JSON file
    pub async fn save_learning_cache(&self) -> Result<()> {
        if let Some(ref path) = self.persist_file {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Read from persist_data shadow copy
            let mut data: HashMap<String, bool> = HashMap::new();
            for entry in self.persist_data.iter() {
                data.insert(entry.key().clone(), *entry.value());
            }
            let count = data.len();

            // Serialize and write to file
            let json = serde_json::to_string_pretty(&data)?;
            std::fs::write(path, json)?;

            info!(
                "📦 SmartForward '{}': Saved {} learning entries to {:?}",
                self.name, count, path
            );
        }
        Ok(())
    }

    fn trim_persist_data(persist_data: &DashMap<String, bool>, max_entries: usize) {
        let current = persist_data.len();
        if current <= max_entries {
            return;
        }
        let mut to_remove = current - max_entries;
        let mut keys: Vec<String> = Vec::with_capacity(to_remove);
        for entry in persist_data.iter() {
            if to_remove == 0 {
                break;
            }
            keys.push(entry.key().clone());
            to_remove -= 1;
        }
        for key in keys {
            persist_data.remove(&key);
        }
    }

    /// Record a learning result (updates both cache and persist_data)
    pub fn record_learning(&self, domain: &str, is_cn: bool) {
        let domain = crate::autopilot::normalize_domain_lower(domain);
        let domain_clean = domain.as_ref().trim_end_matches('.');
        if domain_clean.is_empty() {
            return;
        }
        let domain_owned = domain_clean.to_string();

        if self
            .learning_tx
            .try_send((domain_owned.clone(), is_cn))
            .is_ok()
        {
            return;
        }

        let persist_enabled = self.persist_file.is_some();
        let persist_max_entries = self.persist_max_entries;

        // Fallback: async insert without blocking the hot path
        if tokio::runtime::Handle::try_current().is_err() {
            if persist_enabled {
                self.persist_data.insert(domain_owned.clone(), is_cn);
                Self::trim_persist_data(self.persist_data.as_ref(), persist_max_entries);
            }
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(DOMAIN_CLASS_CACHE_TTL_SECS);
            self.domain_cache.insert(domain_owned, (is_cn, expires_at));
            return;
        }

        let cache = self.learning_cache.clone();
        let persist = self.persist_data.clone();
        let domain_cache = self.domain_cache.clone();
        tokio::spawn(async move {
            cache.insert(domain_owned.clone(), is_cn).await;
            if persist_enabled {
                persist.insert(domain_owned.clone(), is_cn);
                Self::trim_persist_data(persist.as_ref(), persist_max_entries);
            }
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(DOMAIN_CLASS_CACHE_TTL_SECS);
            domain_cache.insert(domain_owned, (is_cn, expires_at));
        });
    }

    /// Start background persistence task (saves every 5 minutes)
    pub fn start_persistence_task(self: Arc<Self>) {
        if self.persist_file.is_none() {
            return; // No persistence configured
        }

        let plugin = self.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(300); // 5 minutes
            let mut last_count = 0usize;

            loop {
                tokio::time::sleep(interval).await;

                // Only save if there are new entries
                let current_count = plugin.persist_data.len();
                if current_count > last_count {
                    if let Err(e) = plugin.save_learning_cache().await {
                        warn!(
                            "⚠️ SmartForward '{}': Persistence task failed: {}",
                            plugin.name, e
                        );
                    }
                    last_count = current_count;
                }
            }
        });

        info!(
            "🔄 SmartForward '{}': Started background persistence task (every 5 min)",
            self.name
        );
    }

    async fn exchange_upstream(
        &self,
        upstream: &Upstream,
        req_bytes: &Bytes,
        timeout: Duration,
    ) -> Result<Message> {
        match tokio::time::timeout(timeout, upstream.exchange_bytes(req_bytes)).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow::anyhow!("Timeout")),
        }
    }

    async fn exchange_target(
        &self,
        target: &SmartForwardTarget,
        req: &Message,
        req_bytes: &Bytes,
        client_ip: IpAddr,
    ) -> Result<Message> {
        match target {
            SmartForwardTarget::Single {
                upstream, timeout, ..
            } => self.exchange_upstream(upstream, req_bytes, *timeout).await,
            SmartForwardTarget::Group { forward, .. } => {
                forward
                    .execute_with_bytes(req, req_bytes, Some(client_ip))
                    .await
            }
        }
    }

    fn get_domain_cache(&self, domain: &str) -> Option<bool> {
        let domain_clean = domain.trim_end_matches('.');
        if let Some(entry) = self.domain_cache.get(domain_clean) {
            let (is_cn, expires_at) = *entry.value();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if expires_at >= now {
                return Some(is_cn);
            }
        }
        self.domain_cache.remove(domain_clean);
        None
    }

    async fn classify_response(&self, resp: &Message) -> (bool, bool) {
        let mut is_cn = false;
        let mut has_ip = false;
        let mut has_cname = false; // 🔧 新增：跟踪 CNAME 记录

        // ① 首先检查 ANSWERS 部分（包含 A/AAAA/CNAME）
        for ans in resp.answers() {
            let data = ans.data();

            // 检查 CNAME
            if data.as_cname().is_some() {
                has_cname = true;
                debug!("📝 Found CNAME in answers: {}", ans.name());
                continue; // CNAME 本身不包含 IP，继续检查其他记录
            }

            // 检查 A/AAAA
            let ip = if let Some(a) = data.as_a() {
                Some(IpAddr::V4(a.0))
            } else if let Some(aaaa) = data.as_aaaa() {
                Some(IpAddr::V6(aaaa.0))
            } else {
                None
            };

            if let Some(ip) = ip {
                has_ip = true;

                if let Some(cached) = self.ip_class_cache.get(&ip) {
                    if cached {
                        is_cn = true;
                        break;
                    }
                    continue;
                }

                // ① 优先使用 ip_matcher（高精度txt列表，<1微秒）
                if let Some(ref matcher) = self.ip_matcher {
                    if matcher.matches(ip) {
                        debug!("✅ IP Matcher: {} is CN (fast path)", ip);
                        self.ip_class_cache.insert(ip, true);
                        is_cn = true;
                        break;
                    }
                }

                // ② 如果 ip_matcher 未命中，使用 GeoIP 兜底（10-50微秒）
                if !is_cn && self.geoip.is_match(ip).await {
                    debug!("✅ GeoIP: {} is CN (fallback path)", ip);
                    self.ip_class_cache.insert(ip, true);
                    is_cn = true;
                    break;
                }

                self.ip_class_cache.insert(ip, false);
            }
        }

        // ② 如果 ANSWERS 中没有 IP，检查 ADDITIONAL 部分（CNAME 后的目标 IP）
        if !has_ip {
            for ans in resp.additionals() {
                let data = ans.data();

                // 跳过非 A/AAAA 记录
                let ip = if let Some(a) = data.as_a() {
                    Some(IpAddr::V4(a.0))
                } else if let Some(aaaa) = data.as_aaaa() {
                    Some(IpAddr::V6(aaaa.0))
                } else {
                    None
                };

                if let Some(ip) = ip {
                    has_ip = true;
                    debug!(
                        "🔍 Found IP in ADDITIONAL section: {} (from CNAME target)",
                        ip
                    );

                    if let Some(cached) = self.ip_class_cache.get(&ip) {
                        if cached {
                            is_cn = true;
                            break;
                        }
                        continue;
                    }

                    // ① 优先使用 ip_matcher
                    if let Some(ref matcher) = self.ip_matcher {
                        if matcher.matches(ip) {
                            debug!("✅ IP Matcher (Additional): {} is CN", ip);
                            self.ip_class_cache.insert(ip, true);
                            is_cn = true;
                            break;
                        }
                    }

                    // ② GeoIP 兜底
                    if !is_cn && self.geoip.is_match(ip).await {
                        debug!("✅ GeoIP (Additional): {} is CN", ip);
                        self.ip_class_cache.insert(ip, true);
                        is_cn = true;
                        break;
                    }

                    self.ip_class_cache.insert(ip, false);
                }
            }
        }

        // 🔧 如果有 CNAME 但最终无 IP，记录日志（可能是 CNAME 链未完全解析）
        if has_cname && !has_ip {
            debug!("⚠️ classify_response: Found CNAME but no IP answers (CNAME chain may be incomplete)");
        }

        (is_cn, has_ip)
    }

    fn is_domestic_domain_lower(&self, qname_lower: &str, ranges: &[(usize, usize)]) -> bool {
        let domain = qname_lower.trim_end_matches('.');
        if self.domestic_suffix_labels.is_empty() {
            return domain.ends_with(".cn");
        }

        if ranges.is_empty() {
            return false;
        }

        let label_count = ranges.len();
        for suffix in &self.domestic_suffix_labels {
            let s_len = suffix.len();
            if s_len == 0 || s_len > label_count {
                continue;
            }
            let mut matched = true;
            for i in 0..s_len {
                let (start, end) = ranges[label_count - s_len + i];
                if end > domain.len() {
                    matched = false;
                    break;
                }
                let label = &qname_lower[start..end];
                if label != suffix[i] {
                    matched = false;
                    break;
                }
            }
            if matched {
                return true;
            }
        }
        false
    }
}

impl Plugin for SmartForwardPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let request = &ctx.request;
        let id = request.id();
        let client_ip = ctx.client_addr.ip();

        // Extract query name for caching
        let qname = if request.query().is_some() {
            ctx.qname_ref()
        } else {
            return Ok(());
        };
        let req_bytes = if let Some(raw) = ctx.request_bytes() {
            raw.clone()
        } else {
            Bytes::from(request.to_vec()?)
        };

        // 记录域名热度与时间模式，增强 AI 学习
        let qname_lower = ctx.qname_lower_ref();
        let qname_ranges = ctx.qname_parts_ranges();
        crate::autopilot::record_domain_query_lower(qname_lower);
        crate::autopilot::record_timed_access_lower(qname_lower);

        // --- Step -1: AI 域名记忆快速通道 (基于 AutoPilot) ---
        let local_label = self.local_label.as_str();
        let fake_label = self.fake_label.as_str();
        if let Some(best_label) =
            crate::autopilot::get_domain_best_upstream_for_client_lower(qname_lower, client_ip)
                .or_else(|| crate::autopilot::get_domain_best_upstream_lower(qname_lower))
        {
            if self.local.matches_label(&best_label) {
                debug!("🤖 AI记忆命中: {} → Local", qname);
                let start = Instant::now();
                match self
                    .exchange_target(&self.local, request, &req_bytes, client_ip)
                    .await
                {
                    Ok(mut resp) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        crate::autopilot::record_success(local_label, elapsed);
                        crate::autopilot::record_domain_result_for_client_lower(
                            qname_lower,
                            local_label,
                            elapsed,
                            client_ip,
                        );
                        self.record_learning(qname_lower, true);
                        resp.set_id(id);
                        ctx.set_response(resp, true);
                        return Ok(());
                    }
                    Err(_) => {
                        crate::autopilot::record_failure(local_label);
                        warn!("⚠️ AI记忆命中但 Local 失败，回退探测流程: {}", qname);
                    }
                }
            } else if self.fakeip.matches_label(&best_label) {
                // 🔒 [安全检查] 即使 AI 记忆说是 Global，也要检查国内域名后缀保护
                if self.avoid_fakeip_on_domestic
                    && self.is_domestic_domain_lower(qname_lower, qname_ranges)
                {
                    debug!(
                        "🛡️ AI记忆被纠正: {} 匹配国内后缀，强制走 Local (避免 FakeIP)",
                        qname
                    );
                    let start = Instant::now();
                    match self
                        .exchange_target(&self.local, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(local_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                local_label,
                                elapsed,
                                client_ip,
                            );
                            // 修正学习缓存为 CN
                            self.record_learning(qname_lower, true);
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(local_label);
                            warn!("⚠️ 强制 Local 失败，回退探测流程: {}", qname);
                        }
                    }
                } else {
                    debug!("🤖 AI记忆命中: {} → FakeIP", qname);
                    let start = Instant::now();
                    match self
                        .exchange_target(&self.fakeip, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(fake_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                fake_label,
                                elapsed,
                                client_ip,
                            );
                            self.record_learning(qname_lower, false);
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(fake_label);
                            warn!("⚠️ AI记忆命中但 FakeIP 失败，回退探测流程: {}", qname);
                        }
                    }
                }
            }
        }

        // --- Step 0: Check Fast Domain Cache ---
        if let Some(is_cn) = self.get_domain_cache(qname_lower) {
            if is_cn {
                debug!(
                    "🧠 SmartForward (Cached): {} is CN. Routing to Local.",
                    qname
                );
                STATS.record_strategy("SmartDNS-Cached");

                let start = Instant::now();
                match self
                    .exchange_target(&self.local, request, &req_bytes, client_ip)
                    .await
                {
                    Ok(mut resp) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        crate::autopilot::record_success(local_label, elapsed);
                        crate::autopilot::record_domain_result_for_client_lower(
                            qname_lower,
                            local_label,
                            elapsed,
                            client_ip,
                        );
                        resp.set_id(id);
                        ctx.set_response(resp, true);
                        return Ok(());
                    }
                    Err(_) => {
                        crate::autopilot::record_failure(local_label);
                        warn!(
                            "⚠️ SmartForward (Cached): Local lookup failed. Falling back to probe."
                        );
                    }
                }
            } else {
                if self.avoid_fakeip_on_domestic
                    && self.is_domestic_domain_lower(qname_lower, qname_ranges)
                {
                    debug!(
                        "🛡️ Cached纠正: {} 匹配国内后缀，强制走 Local (避免 FakeIP)",
                        qname
                    );
                    STATS.record_strategy("SmartDNS-Cached-Corrected");

                    let start = Instant::now();
                    match self
                        .exchange_target(&self.local, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(local_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                local_label,
                                elapsed,
                                client_ip,
                            );
                            self.record_learning(qname_lower, true);
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(local_label);
                            warn!("⚠️ 强制 Local 失败，回退探测流程: {}", qname);
                        }
                    }
                } else {
                    debug!(
                        "🧠 SmartForward (Cached): {} is Global. Routing to FakeIP.",
                        qname
                    );
                    STATS.record_strategy("Proxy-Cached");
                    let start = Instant::now();
                    match self
                        .exchange_target(&self.fakeip, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(fake_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                fake_label,
                                elapsed,
                                client_ip,
                            );
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(fake_label);
                            warn!("⚠️ SmartForward (Cached): FakeIP lookup failed. Falling back to probe.");
                        }
                    }
                }
            }
        }

        // --- Step 0.5: Check Auto-Learning Cache ---
        if let Some(is_cn) = self.learning_cache.get(qname_lower).await {
            if is_cn {
                debug!(
                    "🧠 SmartForward (Learned): {} is CN. Routing to Local.",
                    qname
                );
                STATS.record_strategy("SmartDNS-Learned");

                // Directly query Local, no probing check needed
                // Note: We still query to get the actual IPs, but we skip the "FakeIP fallback" path logic
                let start = Instant::now();
                match self
                    .exchange_target(&self.local, request, &req_bytes, client_ip)
                    .await
                {
                    Ok(mut resp) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        crate::autopilot::record_success(local_label, elapsed);
                        crate::autopilot::record_domain_result_for_client_lower(
                            qname_lower,
                            local_label,
                            elapsed,
                            client_ip,
                        );
                        resp.set_id(id);
                        ctx.set_response(resp, true);
                        return Ok(());
                    }
                    Err(_) => {
                        crate::autopilot::record_failure(local_label);
                        // If cached route fails, maybe fallback to standard logic?
                        // For now, let's fallthrough to standard probe as self-healing.
                        warn!("⚠️ SmartForward (Learned): Local lookup failed. Falling back to probe.");
                    }
                }
            } else {
                // 🔒 [安全检查] 学习缓存标记为 Global，但要检查国内域名后缀保护
                if self.avoid_fakeip_on_domestic
                    && self.is_domestic_domain_lower(qname_lower, qname_ranges)
                {
                    debug!(
                        "🛡️ 学习缓存被纠正: {} 匹配国内后缀，强制走 Local (避免 FakeIP)",
                        qname
                    );
                    STATS.record_strategy("SmartDNS-Learned-Corrected");

                    let start = Instant::now();
                    match self
                        .exchange_target(&self.local, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(local_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                local_label,
                                elapsed,
                                client_ip,
                            );
                            // 修正学习缓存为 CN
                            self.record_learning(qname_lower, true);
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(local_label);
                            warn!("⚠️ 强制 Local 失败，回退探测流程: {}", qname);
                        }
                    }
                } else {
                    debug!(
                        "🧠 SmartForward (Learned): {} is Global. Routing to FakeIP.",
                        qname
                    );
                    STATS.record_strategy("Proxy-Learned");
                    let start = Instant::now();
                    match self
                        .exchange_target(&self.fakeip, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut resp) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(fake_label, elapsed);
                            crate::autopilot::record_domain_result_for_client_lower(
                                qname_lower,
                                fake_label,
                                elapsed,
                                client_ip,
                            );
                            resp.set_id(id);
                            ctx.set_response(resp, true);
                            return Ok(());
                        }
                        Err(_) => {
                            crate::autopilot::record_failure(fake_label);
                            warn!("⚠️ SmartForward (Learned): FakeIP lookup failed. Falling back to probe.");
                        }
                    }
                }
            }
        }

        // ... If cache miss or lookup failed, proceed to standard probing ...

        // 🔧 [Bug Fix] 保存本地探测结果，用于国内域名保护回退
        let mut local_resp_for_fallback: Option<Message> = None;

        // Step 1: Query Local Upstream (The Probe)
        debug!(
            "🕵️ SmartForward: Probing with Local Upstream for {}...",
            qname
        );
        let probe_start = Instant::now();
        let local_res = self
            .exchange_target(&self.local, request, &req_bytes, client_ip)
            .await;

        match local_res {
            Ok(mut local_resp) => {
                let probe_elapsed = probe_start.elapsed().as_millis() as u64;
                crate::autopilot::record_success(local_label, probe_elapsed);
                let (is_cn, has_ip) = self.classify_response(&local_resp).await;

                // Decision Logic
                if is_cn {
                    debug!("🇨🇳 SmartForward: IP is CN. Returning Real IP.");
                    STATS.record_strategy("SmartDNS");

                    // LEARN: This domain is CN
                    self.record_learning(qname_lower, true);
                    crate::autopilot::record_domain_result_for_client_lower(
                        qname_lower,
                        local_label,
                        probe_elapsed,
                        client_ip,
                    );

                    local_resp.set_id(id);
                    ctx.set_response(local_resp, true);
                    return Ok(());
                } else if has_ip && self.prefer_local_on_miss {
                    warn!(
                        "🛡️ SmartForward: prefer_local_on_miss enabled, returning local IP for '{}'",
                        qname
                    );
                    // Treat as domestic for learning to avoid repeated FakeIP
                    self.record_learning(qname_lower, true);
                    crate::autopilot::record_domain_result_for_client_lower(
                        qname_lower,
                        local_label,
                        probe_elapsed,
                        client_ip,
                    );
                    local_resp.set_id(id);
                    ctx.set_response(local_resp, true);
                    return Ok(());
                } else if !has_ip {
                    // No IP (NXDOMAIN, TXT, CNAME-only, etc.)
                    // 🔧 [Bug Fix] 保存本地响应，用于后续回退
                    local_resp_for_fallback = Some(local_resp.clone());

                    // Conservative approach: If NOERROR, maybe accept it?
                    // But for now, stick to original logic: Fallthrough to FakeIP
                    // UNLESS it's NXDOMAIN?
                    if local_resp.response_code() == ResponseCode::NXDomain {
                        // Local says domain doesn't exist.
                        // It MIGHT exist globally. Let's try FakeIP.
                    }
                    debug!("🤔 SmartForward: No IP found in local response. Fallback to FakeIP.");
                } else {
                    debug!("🌏 SmartForward: IP is Foreign. Switching to FakeIP...");
                    // LEARN: This domain is Global
                    self.record_learning(qname_lower, false);
                    // 🔧 [Bug #6 Fix - 保守版本] 只对国内后缀域名保存响应
                    // 这样可以避免影响国外域名的正常流程
                    if self.is_domestic_domain_lower(qname_lower, qname_ranges) {
                        local_resp_for_fallback = Some(local_resp.clone());
                    }
                }
            }
            Err(e) => {
                crate::autopilot::record_failure(local_label);
                warn!(
                    "⚠️ SmartForward: Local probe failed ({}). Trying fallback...",
                    e
                );

                if let Some(fallback) = &self.local_fallback {
                    let fb_label = self
                        .local_fallback_label
                        .as_deref()
                        .unwrap_or_else(|| fallback.label());
                    let fb_start = Instant::now();
                    match self
                        .exchange_target(fallback, request, &req_bytes, client_ip)
                        .await
                    {
                        Ok(mut fb_resp) => {
                            let fb_elapsed = fb_start.elapsed().as_millis() as u64;
                            crate::autopilot::record_success(fb_label, fb_elapsed);
                            let (is_cn, has_ip) = self.classify_response(&fb_resp).await;

                            if is_cn {
                                debug!("🧯 SmartForward: Fallback returned CN IP.");
                                STATS.record_strategy("SmartDNS-Fallback");
                                self.record_learning(qname_lower, true);
                                // 🔧 [Bug Fix] 记录到 fb_label，不是 local_label
                                crate::autopilot::record_domain_result_for_client_lower(
                                    qname_lower,
                                    fb_label,
                                    fb_elapsed,
                                    client_ip,
                                );
                                fb_resp.set_id(id);
                                ctx.set_response(fb_resp, true);
                                return Ok(());
                            } else if has_ip && self.prefer_local_on_miss {
                                warn!(
                                    "🛡️ SmartForward: prefer_local_on_miss enabled, returning fallback IP for '{}'",
                                    qname
                                );
                                self.record_learning(qname_lower, true);
                                crate::autopilot::record_domain_result_for_client_lower(
                                    qname_lower,
                                    fb_label,
                                    fb_elapsed,
                                    client_ip,
                                );
                                fb_resp.set_id(id);
                                ctx.set_response(fb_resp, true);
                                return Ok(());
                            } else if !has_ip {
                                // 🔧 [Bug Fix] 保存 fallback 响应
                                local_resp_for_fallback = Some(fb_resp.clone());

                                if fb_resp.response_code() == ResponseCode::NXDomain {
                                    // Keep conservative behavior, fallthrough to FakeIP
                                }
                                debug!("🧯 SmartForward: Fallback no IP. Continue FakeIP.");
                            } else {
                                debug!(
                                    "🧯 SmartForward: Fallback indicates Foreign. Continue FakeIP."
                                );
                                self.record_learning(qname_lower, false);
                                // 🔧 [Bug #6 Fix - 保守版本] 只对国内后缀域名保存响应
                                if self.is_domestic_domain_lower(qname_lower, qname_ranges) {
                                    local_resp_for_fallback = Some(fb_resp.clone());
                                }
                            }
                        }
                        Err(err) => {
                            crate::autopilot::record_failure(fb_label);
                            warn!(
                                "⚠️ SmartForward: Fallback failed ({}). Continue FakeIP.",
                                err
                            );
                        }
                    }
                } else {
                    warn!("⚠️ SmartForward: No fallback configured. Continue FakeIP.");
                }
            }
        }

        // Step 3: Query FakeIP Upstream (The Injection)
        // 🔧 [Bug #6 Fix] 检查国内域名保护
        if self.avoid_fakeip_on_domestic && self.is_domestic_domain_lower(qname_lower, qname_ranges)
        {
            // 🔧 [关键修复] 如果本地响应有效，返回本地响应而不是 SERVFAIL
            // 这包括两种情况：
            // 1. 本地返回无 IP（NXDOMAIN/CNAME-only）
            // 2. 本地返回国外 IP（如 apple.cn 托管在美国）
            if let Some(mut local_resp) = local_resp_for_fallback {
                warn!("🛡️ SmartForward: Domestic domain '{}', returning local response (avoid FakeIP, IP may be foreign-hosted)", qname);
                local_resp.set_id(id);
                ctx.set_response(local_resp, true);
                return Ok(());
            } else {
                // 本地完全失败（超时/网络错误），返回 SERVFAIL
                warn!(
                    "🚫 SmartForward: Domestic domain '{}' and local failed, returning SERVFAIL",
                    qname
                );
                let mut resp = Message::new();
                resp.set_id(id);
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                resp.set_response_code(ResponseCode::ServFail);
                if let Some(q) = request.query() {
                    resp.add_query(q.clone());
                }
                ctx.set_response(resp, true);
                return Ok(());
            }
        }

        let fake_start = Instant::now();
        let fake_res = self
            .exchange_target(&self.fakeip, request, &req_bytes, client_ip)
            .await;

        match fake_res {
            Ok(mut fake_resp) => {
                let fake_elapsed = fake_start.elapsed().as_millis() as u64;
                debug!("🎭 SmartForward: Returning FakeIP.");
                STATS.record_strategy("Proxy");
                crate::autopilot::record_success(fake_label, fake_elapsed);
                crate::autopilot::record_domain_result_for_client_lower(
                    qname_lower,
                    fake_label,
                    fake_elapsed,
                    client_ip,
                );
                fake_resp.set_id(id);
                ctx.set_response(fake_resp, true);
                Ok(())
            }
            Err(e) => {
                crate::autopilot::record_failure(fake_label);
                warn!("❌ SmartForward: FakeIP upstream also failed: {}", e);
                let mut resp = Message::new();
                resp.set_id(id);
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                resp.set_response_code(ResponseCode::ServFail);
                ctx.set_response(resp, true);
                Ok(())
            }
        }
    }
}

