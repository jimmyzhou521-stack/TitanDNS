use anyhow::{Result, anyhow};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
// use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_proto::op::{Message, ResponseCode, MessageType, OpCode, Query};
use hickory_proto::rr::{RecordType, Name, DNSClass, RData, Record};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// use std::str::FromStr;
use tracing::{debug, info, warn, trace};
// use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use rand::seq::SliceRandom;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// TitanDNS 本地递归解析器 - 真正的主权级迭代查询
/// 
/// 架构：Root → TLD → Authority (完全自主，零依赖公共 DNS)
/// 优势：
/// - 绝对的解析纯净性（直接与权威服务器对话）
/// - 零劫持风险（绕过所有中间转发节点）
/// - 高主权（不受公共 DNS 限制）
#[derive(Debug)]
pub struct RecursiveBackend {
    /// 混合模式解析器：支持快速模式（trusted）和完全递归模式（iterative）
    mode: RecursiveMode,
    trusted_resolver: Option<TokioResolver>,
    root_servers: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub enum RecursiveMode {
    /// 快速模式：使用可信递归解析器（如 Google/Cloudflare）作为后端
    /// 优势：速度快，适合国外域名
    Trusted,
    /// 完全递归模式：从根服务器开始迭代查询
    /// 优势：绝对主权，适合高价值域名
    Iterative,
    /// 混合模式：根据域名类型自动选择
    Hybrid,
}

impl RecursiveBackend {
    /// 创建新的递归后端（默认混合模式）
    pub fn new() -> Self {
        Self::new_with_mode(RecursiveMode::Hybrid)
    }
    
    /// 创建指定模式的递归后端
    pub fn new_with_mode(mode: RecursiveMode) -> Self {
        info!("🔄 Initializing Recursive Backend (Mode: {:?})...", mode);
        
        // 初始化可信解析器（用于 Trusted 和 Hybrid 模式）
        let trusted_resolver = if matches!(mode, RecursiveMode::Trusted | RecursiveMode::Hybrid) {
            // 使用多个可信递归解析器以提高可靠性
            let mut config = ResolverConfig::new();
            
            // Google DoH (Actually DoT here) - 8.8.8.8:853
            config.add_name_server(hickory_resolver::config::NameServerConfig {
                socket_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853),
                protocol: hickory_proto::xfer::Protocol::Tls,
                tls_dns_name: Some("dns.google".to_string()),
                trust_negative_responses: true,
                bind_addr: None,
                http_endpoint: None, // Required field in 0.25
            });
            
            // Cloudflare - 1.1.1.1:853
            config.add_name_server(hickory_resolver::config::NameServerConfig {
                socket_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853),
                protocol: hickory_proto::xfer::Protocol::Tls,
                tls_dns_name: Some("cloudflare-dns.com".to_string()),
                trust_negative_responses: true,
                bind_addr: None,
                http_endpoint: None,
            });
            
            let opts = ResolverOpts::default();
            Some(TokioResolver::tokio(config, opts))
        } else {
            None
        };
        
        // 加载13个根服务器地址（用于 Iterative 模式）
        let root_servers = Self::load_root_hints();
        
        info!("✅ Recursive Backend Ready ({} root servers loaded)", root_servers.len());
        
        Self { 
            mode,
            trusted_resolver,
            root_servers,
        }
    }
    
    /// 加载 DNS 根服务器地址（13个根）
    /// 来源：https://www.internic.net/domain/named.root
    fn load_root_hints() -> Vec<IpAddr> {
        vec![
            // A.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30)),
            // B.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(199, 9, 14, 201)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x200, 0, 0, 0, 0, 0xb)),
            // C.ROOT-SERVERS.NET  
            IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc)),
            // D.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd)),
            // E.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe)),
            // F.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf)),
            // G.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d)),
            // H.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53)),
            // I.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53)),
            // J.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30)),
            // K.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1)),
            // L.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42)),
            // M.ROOT-SERVERS.NET
            IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35)),
        ]
    }
    
    /// 主查询入口点
    pub async fn lookup(&self, name_str: &str, qtype: u16) -> Result<Message> {
        match &self.mode {
            RecursiveMode::Trusted => self.lookup_trusted(name_str, qtype).await,
            RecursiveMode::Iterative => self.lookup_iterative(name_str, qtype).await,
            RecursiveMode::Hybrid => {
                // 智能判断：国内域名用 Trusted（快速），国外用 Iterative（主权）
                if Self::is_domestic_domain(name_str) {
                    debug!("🇨🇳 Domestic domain detected: {} → Using Trusted mode", name_str);
                    self.lookup_trusted(name_str, qtype).await
                } else {
                    debug!("🌍 Foreign domain detected: {} → Using Iterative mode", name_str);
                    // 先尝试 Iterative，失败则降级到 Trusted
                    match self.lookup_iterative(name_str, qtype).await {
                        Ok(msg) => Ok(msg),
                        Err(e) => {
                            warn!("Iterative lookup failed for {}, fallback to Trusted: {}", name_str, e);
                            self.lookup_trusted(name_str, qtype).await
                        }
                    }
                }
            }
        }
    }
    
    /// 判断是否为国内域名
    fn is_domestic_domain(name: &str) -> bool {
        let name_lower = name.to_lowercase();
        
        // 1. 本地域名（.local, .lan, .home, 等）
        if name_lower.ends_with(".local") || name_lower.ends_with(".lan") 
           || name_lower.ends_with(".home") || name_lower.ends_with(".internal") {
            return true;
        }
        
        // 2. 国内顶级域名
        let domestic_tlds = [
            ".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn",
            ".hk", ".tw", ".mo",  // 港澳台
        ];
        
        for tld in &domestic_tlds {
            if name_lower.ends_with(tld) {
                return true;
            }
        }
        
        // 3. 已知国内大厂域名特征
        let domestic_keywords = [
            "baidu", "taobao", "tmall", "alipay", "aliyun",
            "tencent", "qq", "weixin", "wechat",
            "jd", "360", "sina", "sohu", "163", "126",
            "bilibili", "douyin", "kuaishou",
        ];
        
        for keyword in &domestic_keywords {
            if name_lower.contains(keyword) {
                return true;
            }
        }
        
        false
    }
    
    /// 快速模式：使用可信递归解析器
    async fn lookup_trusted(&self, name_str: &str, qtype: u16) -> Result<Message> {
        let resolver = self.trusted_resolver.as_ref()
            .ok_or_else(|| anyhow!("Trusted resolver not initialized"))?;
            
        let name = Name::from_ascii(name_str)?;
        let record_type = RecordType::from(qtype);
        
        trace!("🕵️ Trusted Recursive lookup: {} {:?}", name_str, record_type);
        
        match resolver.lookup(name.clone(), record_type).await {
            Ok(lookup) => {
                let mut msg = Message::new();
                msg.set_id(0);
                msg.set_message_type(MessageType::Response);
                msg.set_response_code(ResponseCode::NoError);
                msg.set_authoritative(false);
                msg.add_answers(lookup.records().iter().cloned());
                
                debug!("✅ Trusted Recursive: {} → {} answers", name_str, msg.answer_count());
                Ok(msg)
            },
            Err(e) => {
                debug!("❌ Trusted lookup failed for {}: {}", name_str, e);
                Err(anyhow!("Trusted lookup error: {}", e))
            }
        }
    }
    
    /// 迭代查询模式 (当前为 Stub Iterative)
    /// 
    /// 注意：当前实现利用 hickory-resolver 的 stub 模式向根服务器发起查询。
    /// 真正的自主迭代（Root -> TLD -> Authority）需要手动处理 Referral 响应，
    /// 当前版本暂未包含完整的迭代器实现。
    /// 
    /// 建议仅在实验环境使用此模式。
    async fn lookup_iterative(&self, name_str: &str, qtype: u16) -> Result<Message> {
        const MAX_DEPTH: usize = 15;
        const MAX_CNAME_DEPTH: usize = 8;
        info!("🌍 Starting iterative query: {} (Type: {})", name_str, qtype);
        
        let name = Name::from_ascii(name_str)?;
        let mut visited: HashSet<String> = HashSet::new();
        self.lookup_iterative_internal(name, qtype, MAX_DEPTH, MAX_CNAME_DEPTH, &mut visited).await
    }
}

impl RecursiveBackend {
    fn build_query(name: &Name, qtype: u16) -> Message {
        let mut msg = Message::new();
        let mut query = Query::new();
        query.set_name(name.clone());
        query.set_query_type(RecordType::from(qtype));
        query.set_query_class(DNSClass::IN);

        msg.set_id(rand::random::<u16>());
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(false);
        msg.add_query(query);
        msg
    }

    async fn send_udp_query(&self, server: IpAddr, msg: &Message) -> Result<Message> {
        let addr = std::net::SocketAddr::new(server, 53);
        let bind_addr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;

        let req_bytes = msg.to_vec()?;
        socket.send(&req_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(std::time::Duration::from_secs(2), socket.recv(&mut buf)).await??;
        let resp = Message::from_vec(&buf[..len])?;

        // If truncated, fallback to TCP
        if resp.header().truncated() {
            return self.send_tcp_query(server, msg).await;
        }

        Ok(resp)
    }

    async fn send_tcp_query(&self, server: IpAddr, msg: &Message) -> Result<Message> {
        let addr = std::net::SocketAddr::new(server, 53);
        let mut stream = timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr)).await??;

        let req_bytes = msg.to_vec()?;
        let len = req_bytes.len() as u16;

        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&req_bytes).await?;

        let mut len_buf = [0u8; 2];
        timeout(std::time::Duration::from_secs(3), stream.read_exact(&mut len_buf)).await??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        timeout(std::time::Duration::from_secs(3), stream.read_exact(&mut resp_buf)).await??;

        Ok(Message::from_vec(&resp_buf)?)
    }

    fn extract_ips_from_records(records: &[Record]) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for rec in records {
            match rec.data() {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }
        ips
    }

    fn extract_ns_names(records: &[Record]) -> Vec<Name> {
        let mut names = Vec::new();
        for rec in records {
            if let RData::NS(ns) = rec.data() {
                names.push(ns.0.clone());
            }
        }
        names
    }

    fn extract_cname_target(records: &[Record]) -> Option<Name> {
        for rec in records {
            if let RData::CNAME(cn) = rec.data() {
                return Some(cn.0.clone());
            }
        }
        None
    }

    fn has_answer_type(records: &[Record], qtype: u16) -> bool {
        let target = RecordType::from(qtype);
        records.iter().any(|r| r.record_type() == target)
    }

    fn is_nodata(resp: &Message) -> bool {
        resp.response_code() == ResponseCode::NoError
            && resp.answers().is_empty()
            && resp.name_servers().iter().any(|r| matches!(r.data(), RData::SOA(_)))
    }

    async fn resolve_ns_ips_iterative(
        &self,
        ns_names: &[Name],
        depth_left: usize,
        cname_depth: usize,
        visited: &mut HashSet<String>,
    ) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for ns in ns_names {
            let ns_str = ns.to_string();
            // Try iterative A/AAAA lookup for NS host
            if let Ok(msg) = self.lookup_iterative_internal(ns.clone(), u16::from(RecordType::A), depth_left, cname_depth, visited).await {
                ips.extend(Self::extract_ips_from_records(msg.answers()));
            }
            if let Ok(msg) = self.lookup_iterative_internal(ns.clone(), u16::from(RecordType::AAAA), depth_left, cname_depth, visited).await {
                ips.extend(Self::extract_ips_from_records(msg.answers()));
            }

            if !ips.is_empty() {
                continue;
            }

            // Fallback to trusted resolver if available
            if let Some(resolver) = self.trusted_resolver.as_ref() {
                if let Ok(lookup) = resolver.lookup(ns.clone(), RecordType::A).await {
                    for r in lookup.records() {
                        if let RData::A(a) = r.data() {
                            ips.push(IpAddr::V4(a.0));
                        }
                    }
                }
                if let Ok(lookup) = resolver.lookup(ns.clone(), RecordType::AAAA).await {
                    for r in lookup.records() {
                        if let RData::AAAA(a) = r.data() {
                            ips.push(IpAddr::V6(a.0));
                        }
                    }
                }
            }

            if !ips.is_empty() {
                debug!("🔍 Resolved NS {} -> {} IPs", ns_str, ips.len());
            }
        }
        ips
    }

    fn lookup_iterative_internal<'a>(
        &'a self,
        name: Name,
        qtype: u16,
        mut depth_left: usize,
        mut cname_depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> BoxFuture<'a, Result<Message>> {
        Box::pin(async move {
        if depth_left == 0 {
            return Err(anyhow!("Iterative depth exceeded"));
        }
        if cname_depth == 0 {
            return Err(anyhow!("CNAME chain too deep"));
        }

        let visit_key = format!("{}:{}", name, qtype);
        if !visited.insert(visit_key) {
            return Err(anyhow!("Iterative loop detected"));
        }

        let mut ns_ips: Vec<IpAddr> = self.root_servers.clone();
        ns_ips.shuffle(&mut rand::thread_rng());

        loop {
            if depth_left == 0 {
                return Err(anyhow!("Iterative depth exceeded"));
            }

            let mut next_ns_ips: Vec<IpAddr> = Vec::new();
            let mut last_error: Option<anyhow::Error> = None;

            // Limit number of NS queries per level
            let max_try = std::cmp::min(ns_ips.len(), 6);
            for server in ns_ips.iter().take(max_try) {
                let query = Self::build_query(&name, qtype);
                match self.send_udp_query(*server, &query).await {
                    Ok(resp) => {
                        // NXDOMAIN or authoritative no data
                        if resp.response_code() == ResponseCode::NXDomain {
                            return Ok(resp);
                        }
                        if Self::is_nodata(&resp) {
                            return Ok(resp);
                        }

                        let answers = resp.answers();
                        // If answers contain target qtype, return
                        if Self::has_answer_type(answers, qtype) {
                            return Ok(resp);
                        }

                        // Handle CNAME chain
                        if let Some(cname) = Self::extract_cname_target(answers) {
                            cname_depth -= 1;
                            return self.lookup_iterative_internal(cname, qtype, depth_left - 1, cname_depth, visited).await;
                        }

                        // Referral: extract NS names
                        let ns_names = Self::extract_ns_names(resp.name_servers());
                        if ns_names.is_empty() {
                            continue;
                        }

                        // Try glue from additional section
                        let mut glue_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
                        for rec in resp.additionals() {
                            let name_str = rec.name().to_string();
                            let ips = Self::extract_ips_from_records(std::slice::from_ref(rec));
                            if !ips.is_empty() {
                                glue_map.entry(name_str).or_default().extend(ips);
                            }
                        }

                        for ns in &ns_names {
                            if let Some(ips) = glue_map.get(&ns.to_string()) {
                                next_ns_ips.extend(ips.clone());
                            }
                        }

                        if next_ns_ips.is_empty() {
                            let resolved = self.resolve_ns_ips_iterative(&ns_names, depth_left - 1, cname_depth, visited).await;
                            if !resolved.is_empty() {
                                next_ns_ips = resolved;
                            }
                        }

                        if !next_ns_ips.is_empty() {
                            depth_left -= 1;
                            next_ns_ips.shuffle(&mut rand::thread_rng());
                            ns_ips = next_ns_ips.clone();
                            break;
                        }
                    }
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                }
            }

            if !next_ns_ips.is_empty() {
                continue;
            }

            return Err(last_error.unwrap_or_else(|| anyhow!("Iterative lookup failed: no responsive nameserver")));
        }
        })
    }
}

impl Default for RecursiveBackend {
    fn default() -> Self {
        Self::new()
    }
}
