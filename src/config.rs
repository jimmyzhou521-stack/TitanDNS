use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CachePluginConfig {
    pub size: usize, // Max items
    #[serde(default)]
    pub fakeip_protection: bool, // Prevent caching fake IPs?
    
    // --- Smart Prefetch ---
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>, // Who to ask for refresh?
    #[serde(default)]
    pub prefetch_if_ttl_less_than: u32, // Trigger refresh if TTL < this (seconds)
    #[serde(default)]
    pub serve_stale_ttl: u32, // If expired, still serve if within this seconds (Hot Potato)

    #[serde(default)]
    pub recursive_mode: bool, // Enable Trusted Recursive Refresh

    // --- Disk Persistence ---
    #[serde(default)]
    pub persist_file: Option<String>, // Path to persist cache (e.g. "/var/cache/titandns/domestic.db")
    #[serde(default = "default_persist_interval")]
    pub persist_interval: u64, // How often to save to disk (seconds), default 300
}

fn default_persist_interval() -> u64 { 300 }
fn default_probe_timeout() -> u64 { 100 }
fn default_probe_port() -> u16 { 80 }
fn default_max_probes() -> usize { 5 }
fn default_dga_entropy() -> f64 { 4.5 }
fn default_dga_min_len() -> usize { 12 }
/// Root Configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// Logging configuration
    #[serde(default)]
    pub log: LogConfig,

    /// Query Log (History) configuration
    #[serde(default)]
    pub query_log: QueryLogConfig,

    /// HTTP API configuration (e.g., for cache purging)
    pub api: Option<ApiConfig>,

    /// Sing-box Synergy configuration
    #[serde(default)]
    pub singbox: SingBoxConfig,

    /// Plugins definition (The "Lego bricks")
    #[serde(default)]
    pub plugins: HashMap<String, PluginType>,

    /// Processing Sequences (The "Logic Flows")
    #[serde(default)]
    pub sequences: HashMap<String, Vec<SequenceStep>>,

    /// Server Listeners (UDP/TCP/DoH)
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    /// eBPF Filter Configuration (Linux Only)
    pub ebpf: Option<EbpfConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EbpfConfig {
    pub interface: String,
    pub bpf_path: Option<String>,
    #[serde(default)]
    pub blacklist: Vec<BlacklistEntry>,
    #[serde(default)]
    pub xdp_cache: Option<XdpCacheConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct XdpCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sync_hot_queries: bool,
    #[serde(default)]
    pub max_entries: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlacklistEntry {
    pub ip: String,
    #[serde(default = "default_blacklist_action")]
    pub action: String, // "drop" or "refuse"
}

fn default_blacklist_action() -> String {
    "drop".to_string()
}

impl Config {
    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String, // info, debug, warn
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct QueryLogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_query_log_size")]
    pub max_size: usize,
    #[serde(default = "default_recent_blocked_limit")]
    pub recent_blocked_limit: usize,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enable by default for better UX
            max_size: 5000,
            recent_blocked_limit: 100,
        }
    }
}

fn default_query_log_size() -> usize { 5000 }
fn default_recent_blocked_limit() -> usize { 100 }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    pub http: SocketAddr,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct SingBoxConfig {
    #[serde(default)]
    pub auto_discover: bool,
    pub socks_port: Option<u16>,
    /// Domains that should force-fallback to direct DNS (Anti-deadlock)
    #[serde(default)]
    pub deadlock_domains: Vec<String>,
    pub fallback_dns: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub protocol: Protocol,
    pub addr: String,
    pub entry: String, // Entry sequence tag
    
    // Performance Tuning Options
    #[serde(default)]
    pub socket_opts: SocketOpts,
    
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Udp,
    Tcp,
    Doh,
    Doq,
    Dot,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct SocketOpts {
    #[serde(default)]
    pub so_reuseport: bool,
    #[serde(default)] // Default to 0 (system default), or set specific size e.g. 16777216
    pub so_rcvbuf: usize,
    #[serde(default)]
    pub so_sndbuf: usize,
    #[serde(default)]
    pub batch_io: bool, // Enable recvmmsg
    #[serde(default = "default_workers")]
    pub workers: usize, // Number of parallel UDP workers (0 = auto-detect CPU cores)
}

fn default_workers() -> usize {
    1 // Default single worker for compatibility
}

/// The Core Plugin Registry
/// Uses Enum to strictly type-check plugin arguments at start-up.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum PluginType {
    /// Standard Caching
    #[serde(rename = "cache")]
    Cache {
        size: usize,
        #[serde(default)]
        dump_file: Option<String>,
        #[serde(default)]
        fakeip_protection: bool,  // FakeIP 保护开关
        #[serde(default)]
        upstreams: Vec<UpstreamConfig>,
        #[serde(default)]
        prefetch_if_ttl_less_than: u32,
        #[serde(default)]
        serve_stale_ttl: u32,
        #[serde(default)]
        recursive_mode: bool,
        #[serde(default)]
        persist_file: Option<String>,  // Path for disk persistence
        #[serde(default = "default_persist_interval")]
        persist_interval: u64,  // Interval in seconds for saving to disk
    },
    
    /// Forwarding (The core engine)
    #[serde(rename = "forward")]
    Forward {
        upstreams: Vec<UpstreamConfig>,
        concurrent: Option<usize>, // number of concurrent queries
        strategy: Option<String>,  // race, order, parallel
    },

    /// Reject/Blackhole Plugin (Ad-blocking, Blacklist)
    #[serde(rename = "reject")]
    Reject {
        #[serde(default = "default_reject_rcode")]
        rcode: String, // "nxdomain", "noerror", "blackhole_v4", "blackhole_v6", or IP address
    },

    #[serde(rename = "hosts")]
    Hosts { file: String },

    #[serde(rename = "query_log")]
    QueryLog { file: String },

    /// GeoSite Plugin (Domain Categorization)
    #[serde(rename = "geosite")]
    GeoSite {
        target: String,      // Target category to match (e.g., "cn")
        files: Vec<String>,  // List of geosite.dat/txt files to load
        #[serde(default)]
        mark: Option<String>, // Tag to add on match
    },

    /// GeoIP Plugin (IP-based Tagging)
    #[serde(rename = "geoip")]
    GeoIp {
        file: String,        // Path to Country.mmdb
        code: String,        // ISO Country Code (e.g. "cn")
        tag: String,         // Tag to add if match
        #[serde(default)]
        mode: String,        // "client" or "response" (default: response)
        #[serde(default)]
        invert: bool,
    },

    /// Matcher Plugin (Domain List Matching)
    #[serde(rename = "matcher")]
    Matcher {
        files: Vec<String>,  // List of rule files (one domain per line)
        #[serde(default)]
        mark: Option<String>, // Optional tag to add on match
    },

    /// IP Matcher Plugin (CIDR List Matching for Response IPs)
    #[serde(rename = "ip_matcher")]
    IpMatcher {
        files: Vec<String>,  // List of CIDR rule files (one CIDR per line, e.g., 1.0.1.0/24)
        #[serde(default)]
        mark: Option<String>, // Optional tag to add on match
    },

    /// Fallback Plugin (Primary/Secondary failover)
    #[serde(rename = "fallback")]
    Fallback {
        primary: String,     // Primary upstream plugin name
        secondary: String,   // Secondary upstream plugin name
        #[serde(default = "default_fallback_threshold")]
        threshold: u64,      // Timeout in ms before switching to secondary
        #[serde(default)]
        always_standby: bool, // If true, always query both in parallel
    },

    /// ECS Plugin (EDNS Client Subnet)
    #[serde(rename = "ecs")]
    Ecs {
        #[serde(default)]
        auto: bool,          // Auto-detect client IP
        ipv4_netmask: Option<u8>,
        ipv6_netmask: Option<u8>,
        force_subnet: Option<String>, // Manually specify subnet
    },

    /// FakeIP Plugin (Native fake IP allocation)
    #[serde(rename = "fakeip")]
    FakeIp {
        #[serde(default = "default_fakeip_v4_range")]
        inet4_range: String,    // e.g., "7.0.0.0/8"
        #[serde(default = "default_fakeip_v6_range")]
        inet6_range: String,    // e.g., "fc00::/18"
    },

    /// SmartForward Plugin (Experimental)
    #[serde(rename = "smart_forward")]
    SmartForward {
        /// 单上游（旧配置兼容）
        #[serde(default)]
        local: Option<UpstreamConfig>,
        #[serde(default)]
        fakeip: Option<UpstreamConfig>,
        /// 多上游（增强：支持 Smart 策略）
        #[serde(default)]
        local_upstreams: Vec<UpstreamConfig>,
        #[serde(default)]
        fakeip_upstreams: Vec<UpstreamConfig>,
        #[serde(default)]
        local_strategy: Option<String>,
        #[serde(default)]
        fakeip_strategy: Option<String>,
        #[serde(default)]
        local_concurrent: Option<usize>,
        #[serde(default)]
        fakeip_concurrent: Option<usize>,
        #[serde(default)]
        local_timeout_ms: Option<u64>,
        #[serde(default)]
        fakeip_timeout_ms: Option<u64>,
        #[serde(default)]
        local_fallback_upstreams: Vec<UpstreamConfig>,
        #[serde(default)]
        local_fallback_strategy: Option<String>,
        #[serde(default)]
        local_fallback_concurrent: Option<usize>,
        #[serde(default)]
        local_fallback_timeout_ms: Option<u64>,
        #[serde(default)]
        avoid_fakeip_on_domestic: bool,
        #[serde(default)]
        domestic_suffixes: Vec<String>,
        #[serde(default)]
        ip_matcher: Option<String>, // Reference to an IpMatcher plugin (optional, for speed)
        geoip: String, // Reference to a GeoIP plugin
        /// [新增] Learning Cache 持久化文件路径
        #[serde(default)]
        learning_cache_file: Option<String>,
    },

    /// DNS64 Plugin (IPv4 to IPv6 translation)
    #[serde(rename = "dns64")]
    Dns64 {
        #[serde(default)]
        prefix: Option<String>,  // NAT64 prefix (default: 64:ff9b::/96)
        #[serde(default = "default_true")]
        only_if_no_aaaa: bool,   // Only synthesize if no AAAA records exist
    },

    /// DNSSEC Validation Plugin
    #[serde(rename = "dnssec")]
    Dnssec {
        #[serde(default = "default_dnssec_mode")]
        mode: String,  // "strict", "permissive", or "log"
    },

    /// AdBlock Plugin (AdGuard syntax support)
    #[serde(rename = "adblock")]
    AdBlock {
        files: Vec<String>,
    },

    /// IPv6 Filter Plugin (IPv4/IPv6 priority control)
    #[serde(rename = "ipv6_filter")]
    Ipv6Filter {
        #[serde(default = "default_ipv6_filter_mode")]
        mode: String,  // "prefer_ipv4", "prefer_ipv6", "disable_ipv6", "disabled"
        #[serde(default = "default_ipv6_delay")]
        delay_aaaa_ms: u64,  // Delay in ms for AAAA responses (prefer_ipv4 mode)
    },

    /// DGA (Domain Generation Algorithm) Detection
    #[serde(rename = "dga")]
    Dga {
        #[serde(default = "default_dga_entropy")]
        entropy_threshold: f64,
        #[serde(default = "default_dga_min_len")]
        min_len: usize,
        #[serde(default = "default_true")]
        dry_run: bool, // Default to true (logging only) for safety
    },

    /// SmartResolve Plugin (Concurrent Query + Speed-Based IP Selection)
    #[serde(rename = "smart_resolve")]
    SmartResolve {
        upstreams: Vec<UpstreamConfig>,  // Multiple upstreams to query concurrently
        #[serde(default = "default_probe_timeout")]
        probe_timeout_ms: u64,           // Timeout for IP probing (default: 100ms)
        #[serde(default = "default_probe_port")]
        probe_port: u16,                 // Port for TCP probe (default: 80)
        #[serde(default = "default_true")]
        prefer_ipv4: bool,               // Prefer IPv4 results
        #[serde(default = "default_max_probes")]
        max_ips_to_probe: usize,         // Max IPs to probe (default: 5)
    },

    /// TTL Modifier Plugin (Extend cache lifetime)
    #[serde(rename = "ttl")]
    Ttl {
        #[serde(default)]
        fixed: Option<u32>,     // Fixed TTL value (overrides min/max)
        #[serde(default)]
        min: Option<u32>,       // Minimum TTL
        #[serde(default)]
        max: Option<u32>,       // Maximum TTL
    },

    /// Rate Limiting Plugin (QPS protection)
    #[serde(rename = "ratelimit")]
    RateLimit {
        max_queries: u32,     // Maximum queries per window per IP
        window_secs: u64,     // Time window in seconds
    },

    /// Aliyun HTTPDNS API Plugin (Ultra-low latency)
    #[serde(rename = "aliapi")]
    AliApi {
        account_id: String,
        access_key_id: String,
        access_key_secret: String,
    },

    /// Any other legacy generic plugin
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamConfig {
    pub addr: String,
    pub dial_addr: Option<String>, // For SNI/Host mapping
    pub socks5: Option<String>,    // Proxy support
    pub idle_timeout: Option<u64>,
    #[serde(default)]
    pub so_mark: Option<u32>,      // Kernel socket mark (fwmark)
    #[serde(default)]
    pub tcp_fast_open: bool,       // Enable TCP Fast Open (TFO)
}

/// A Step in a Sequence
/// Replaces the "matches + exec" logic with a cleaner structure
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SequenceStep {
    /// If these conditions match... (Implicit AND)
    #[serde(default)]
    pub matches: Vec<MatchCondition>,
    
    /// Execute this plugin/sequence tag
    pub exec: String, 
    
    /// Arguments for the execution (optional overrides)
    pub args: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum MatchCondition {
    /// Match specific QNames
    ByQname { qname: Vec<String> },
    
    /// Match QType
    ByQtype { qtype: Vec<u16> },
    
    /// Match Client IP
    ByClientIp { client_ip: Vec<String> },
    
    /// Custom Tag matching
    ByTag { 
        has_tag: String,
        #[serde(default)]
        invert: bool,
    },
    
    /// Match using a Matcher plugin
    ByMatcherPlugin { match_plugin: String },
    
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_reject_rcode() -> String {
    "nxdomain".to_string()
}

fn default_fallback_threshold() -> u64 {
    400  // 400ms default timeout
}

fn default_fakeip_v4_range() -> String {
    "7.0.0.0/8".to_string()
}

fn default_fakeip_v6_range() -> String {
    "fc00::/18".to_string()
}

fn default_true() -> bool {
    true
}

fn default_dnssec_mode() -> String {
    "permissive".to_string()
}

fn default_ipv6_filter_mode() -> String {
    "disabled".to_string()
}

fn default_ipv6_delay() -> u64 {
    50  // 50ms default delay for AAAA
}
