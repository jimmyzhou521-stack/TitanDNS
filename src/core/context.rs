use std::net::SocketAddr;
use std::collections::HashSet;
use std::time::Instant;
use std::sync::Arc;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use dashmap::DashMap;
use bytes::Bytes;
use once_cell::sync::{Lazy, OnceCell};
use crate::core::zerocopy::ZeroCopyDnsMessage;


static TAG_INTERN: Lazy<DashMap<String, Arc<str>>> = Lazy::new(DashMap::new);

fn intern_tag(tag: &str) -> Arc<str> {
    if let Some(existing) = TAG_INTERN.get(tag) {
        return existing.clone();
    }
    let owned = tag.to_string();
    let arc: Arc<str> = Arc::from(owned.clone());
    TAG_INTERN.insert(owned, arc.clone());
    arc
}

/// The "Packet" that flows through the plugin pipeline
/// 
/// Supports both traditional `hickory_proto::Message` and zero-copy `ZeroCopyDnsMessage`.
/// Plugins can use either interface during the migration period.
#[derive(Debug, Clone)]
pub struct Context {
    /// Where the DNS query comes from
    pub client_addr: SocketAddr,
    
    /// The decoded DNS Request (hickory format, for compatibility)
    /// TODO: Future optimization - replace with ZeroCopyDnsMessage for zero-allocation parsing
    pub request: Message,
    
    /// [NEW] Raw request bytes (zero-copy, optional)
    /// Plugins that support zero-copy can use this instead of `request`
    pub raw_request: Option<ZeroCopyDnsMessage>,
    
    /// The Response (if any plugin generated one)
    pub response: Option<Message>,
    
    /// [NEW] Raw response bytes (zero-copy, optional)
    /// When set, this takes priority over `response` for sending
    pub raw_response: Option<ZeroCopyDnsMessage>,
    
    /// Tags for logic branching (e.g., "cn", "ad", "proxy")
    pub tags: HashSet<Arc<str>>,
    
    /// Should we stop processing further plugins?
    pub abort: bool,

    /// Enforce a minimum TTL on response records (0 = disable)
    pub min_ttl: u32,

    /// Timestamp when processing started (for latency logging)
    pub start_ts: Instant,

    /// Plugins that want to run AFTER a response is generated (e.g. Cache Write)
    pub post_process_hooks: Vec<crate::plugins::AnyPlugin>,

    /// Cached qname string to avoid repeated allocations
    qname_cache: OnceCell<String>,
    /// Cached lowercase qname for repeated matching
    qname_lower: OnceCell<String>,
    /// Cached qname label ranges (lowercase)
    qname_parts: OnceCell<Vec<(usize, usize)>>,
    /// Cached query type
    qtype_cache: OnceCell<RecordType>,
}

pub struct QnamePartsIter<'a> {
    name: &'a str,
    ranges: std::slice::Iter<'a, (usize, usize)>,
}

impl<'a> Iterator for QnamePartsIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.ranges.next().map(|(s, e)| &self.name[*s..*e])
    }
}

impl Context {
    /// Create Context from parsed Message (legacy path)
    pub fn new(request: Message, client_addr: SocketAddr) -> Self {
        Self {
            client_addr,
            request,
            raw_request: None,
            response: None,
            raw_response: None,
            tags: HashSet::new(),
            abort: false,
            min_ttl: 0,
            start_ts: Instant::now(),
            post_process_hooks: Vec::new(),
            qname_cache: OnceCell::new(),
            qname_lower: OnceCell::new(),
            qname_parts: OnceCell::new(),
            qtype_cache: OnceCell::new(),
        }
    }

    /// [NEW] Create Context from raw bytes (zero-copy path)
    /// Parses the Message lazily when needed
    pub fn from_bytes(data: Bytes, client_addr: SocketAddr) -> Result<Self, anyhow::Error> {
        let zc_msg = ZeroCopyDnsMessage::from_bytes(data.clone())
            .map_err(|e| anyhow::anyhow!(e))?;
        
        // Parse to Message for compatibility (will be lazy in future)
        let request = Message::from_vec(&data)?;
        
        Ok(Self {
            client_addr,
            request,
            raw_request: Some(zc_msg),
            response: None,
            raw_response: None,
            tags: HashSet::new(),
            abort: false,
            min_ttl: 0,
            start_ts: Instant::now(),
            post_process_hooks: Vec::new(),
            qname_cache: OnceCell::new(),
            qname_lower: OnceCell::new(),
            qname_parts: OnceCell::new(),
            qtype_cache: OnceCell::new(),
        })
    }

    /// Helper to get the Question Name (domain) as &str (cached)
    pub fn qname_ref(&self) -> &str {
        self.qname_cache
            .get_or_init(|| {
                if let Some(query) = self.request.query() {
                    return query.name().to_string();
                }
                ".".to_string()
            })
            .as_str()
    }

    /// Helper to get the Question Name (domain) as String
    pub fn qname(&self) -> String {
        self.qname_ref().to_string()
    }

    /// Cached lowercase qname (ASCII only)
    pub fn qname_lower_ref(&self) -> &str {
        self.qname_lower
            .get_or_init(|| {
                let name = self.qname_ref();
                if name.as_bytes().iter().any(|b| b'A' <= *b && *b <= b'Z') {
                    name.to_ascii_lowercase()
                } else {
                    name.to_string()
                }
            })
            .as_str()
    }

    /// Cached lowercase qname label ranges
    pub fn qname_parts_ranges(&self) -> &[(usize, usize)] {
        self.qname_parts.get_or_init(|| {
            let lower = self.qname_lower_ref();
            let bytes = lower.as_bytes();
            let mut ranges = Vec::new();
            let mut start = 0usize;
            for (i, b) in bytes.iter().enumerate() {
                if *b == b'.' {
                    if i > start {
                        ranges.push((start, i));
                    }
                    start = i + 1;
                }
            }
            if start < bytes.len() {
                ranges.push((start, bytes.len()));
            }
            ranges
        })
    }

    /// Zero-alloc iterator over lowercase qname labels
    pub fn qname_parts_iter(&self) -> QnamePartsIter<'_> {
        let name = self.qname_lower_ref();
        let ranges = self.qname_parts_ranges();
        QnamePartsIter { name, ranges: ranges.iter() }
    }

    /// Cached query type
    pub fn qtype(&self) -> RecordType {
        *self.qtype_cache.get_or_init(|| {
            self.request
                .query()
                .map(|q| q.query_type())
                .unwrap_or(RecordType::NULL)
        })
    }

    /// Precompute common query attributes used by plugins
    pub fn precompute(&self) {
        let _ = self.qname_lower_ref();
        let _ = self.qname_parts_ranges();
        let _ = self.qtype();
    }

    /// [NEW] Get raw request bytes (zero-copy if available)
    pub fn request_bytes(&self) -> Option<&Bytes> {
        self.raw_request.as_ref().map(|r| r.raw_bytes())
    }

    /// Check if a specific tag exists
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.insert(intern_tag(tag));
    }

    /// Set the response message and signal that processing should stop (usually)
    /// This also automatically applies optimizations like MinTTL.
    pub fn set_response(&mut self, mut msg: Message, stop_sequence: bool) {
        // Optimization: Enforce MinTTL
        if self.min_ttl > 0 {
            for ans in msg.answers_mut() {
                if ans.ttl() < self.min_ttl {
                    ans.set_ttl(self.min_ttl);
                }
            }
        }
        
        // Ensure ID matches request (critical for UDP match)
        msg.set_id(self.request.id());
        
        self.response = Some(msg);
        self.raw_response = None; // Clear raw response when setting Message
        if stop_sequence {
            self.abort = true;
        }
    }

    /// [NEW] Set response from raw bytes (zero-copy path)
    /// Use this when you have a cached byte response and want to avoid serialization
    pub fn set_raw_response(&mut self, raw: ZeroCopyDnsMessage, stop_sequence: bool) {
        // Ensure ID matches request
        let raw = raw.with_id(self.request.id());
        
        self.raw_response = Some(raw);
        self.response = None; // Clear parsed response
        if stop_sequence {
            self.abort = true;
        }
    }

    /// [NEW] Get final response bytes for sending
    /// Prefers raw_response if available, otherwise serializes response
    pub fn response_bytes(&self) -> Option<Bytes> {
        if let Some(ref raw) = self.raw_response {
            return Some(raw.raw_bytes().clone());
        }
        if let Some(ref resp) = self.response {
            return resp.to_vec().ok().map(Bytes::from);
        }
        None
    }

    /// [NEW] Check if we have any response (raw or parsed)
    pub fn has_response(&self) -> bool {
        self.response.is_some() || self.raw_response.is_some()
    }

    /// [NEW] Get response code (RCODE) as string from either response or raw_response
    /// This ensures zero-copy responses are properly counted in statistics/logging
    pub fn get_rcode_as_string(&self) -> String {
        // First check parsed response
        if let Some(ref resp) = self.response {
            return resp.response_code().to_string();
        }

        // Then check raw response (zero-copy path)
        if let Some(ref raw) = self.raw_response {
            return rcode_to_string(raw.rcode());
        }

        // No response
        "NO_RES".to_string()
    }
}

/// Convert DNS RCODE (u8) to human-readable string
/// Standard DNS response codes as defined in RFC 1035 and others
fn rcode_to_string(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        11 => "DSOTYPENI",
        16 => "BADVERS", // BADVERS is same as BADSIG (16)
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "UNKNOWN",
    }.to_string()
}
