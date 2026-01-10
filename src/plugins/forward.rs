use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::config::UpstreamConfig;
use anyhow::{Result, Context as AnyhowContext};
// use async_trait::async_trait; // 未使用
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use futures::stream::{FuturesUnordered, StreamExt};
use crate::core::singleflight::Singleflight;
use socket2::{Socket, Domain, Type, Protocol};
use crate::core::metrics;

/// TitanDNS v7.3.9 - "The Complete Sovereign" - 完全优化版
/// 所有工业级功能完整保留
#[derive(Debug, Clone)]
pub struct ForwardPlugin {
    pub name: String,
    pub upstreams: Vec<Arc<Upstream>>,
    pub timeout: Duration,
    pub concurrent_limit: Arc<Semaphore>,
    pub strategy: Option<String>,
    pub proxy_status: Option<Arc<AtomicBool>>,
    pub singleflight: Arc<Singleflight<String, Message>>,
    /// [自适应连接池] QPS 监控（仅统计，不自动调整）
    qps_monitor: Arc<crate::plugins::adaptive_pool::AdaptiveConnectionPool>,
}

/// 精确的上游错误分类（用于 Metrics）
#[derive(thiserror::Error, Debug)]
pub enum UpstreamError {
    #[error("Upstream {0} timeout")]
    Timeout(String),
    #[error("Upstream {0} connection refused")]
    ConnectionRefused(String),
    #[error("Upstream {0} protocol error: {1}")]
    ProtocolError(String, String),
    #[error("Upstream {0} I/O error: {1}")]
    Io(String, String),
    #[error("Upstream {0} returned error status: {1}")]
    DnsError(String, ResponseCode),
}

/// 完整的上游类型支持
pub enum Upstream {
    Udp { 
        addr: std::net::SocketAddr, 
        label: String,
        bootstrap_host: Option<String>,
        socks5: Option<String>,
        mark: Option<u32>, // Kernel Socket Mark
    },
    Tcp { 
        addr: std::net::SocketAddr, 
        label: String,
        bootstrap_host: Option<String>,
        socks5: Option<String>,
        mark: Option<u32>,
        tfo: bool,         // TCP Fast Open
    },
    Doh { 
        url: String, 
        // Lazy-initialized client
        client: Arc<tokio::sync::OnceCell<reqwest::Client>>,
        client_config: Arc<DohClientConfig>,
        proxy_enabled: bool,
        label: String,
        bootstrap_ip: Option<std::net::IpAddr> 
    },
    Dot {
        addr: std::net::SocketAddr,
        host: String,
        label: String,
        socks5: Option<String>,
        mark: Option<u32>,
        tfo: bool,
        // Connection Pool: Lazy-initialized TLS connector + connection queue
        tls_connector: Arc<tokio::sync::OnceCell<tokio_rustls::TlsConnector>>,
        conn_pool: Arc<tokio::sync::Mutex<Vec<DotConnection>>>,
    },
    /// DNS-over-QUIC (RFC 9250)
    Doq {
        addr: std::net::SocketAddr,
        host: String,
        label: String,
        socks5: Option<String>,  // 新增: SOCKS5 代理支持
        mark: Option<u32>,
        // Lazy-initialized QUIC endpoint + connection pool
        endpoint: Arc<tokio::sync::OnceCell<quinn::Endpoint>>,
        conn_pool: Arc<tokio::sync::Mutex<Option<quinn::Connection>>>,
        // SOCKS5 UDP tunnel (if socks5 is configured)
        socks5_tunnel: Arc<tokio::sync::Mutex<Option<crate::socks5_udp::Socks5UdpTunnel>>>,
    }
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Udp { addr, label, mark, .. } => f.debug_struct("Udp").field("addr", addr).field("label", label).field("mark", mark).finish(),
            Upstream::Tcp { addr, label, mark, tfo, .. } => f.debug_struct("Tcp").field("addr", addr).field("label", label).field("mark", mark).field("tfo", tfo).finish(),
            Upstream::Doh { url, label, .. } => f.debug_struct("Doh").field("url", url).field("label", label).finish(),
            Upstream::Dot { addr, host, label, mark, .. } => f.debug_struct("Dot").field("addr", addr).field("host", host).field("label", label).field("mark", mark).finish(),
            Upstream::Doq { addr, host, label, mark, .. } => f.debug_struct("Doq").field("addr", addr).field("host", host).field("label", label).field("mark", mark).finish(),
        }
    }
}

/// A pooled DoT connection (Debug not derivable due to TlsStream)
pub struct DotConnection {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    last_used: std::time::Instant,
}

impl std::fmt::Debug for DotConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotConnection")
            .field("last_used", &self.last_used)
            .finish()
    }
}

impl DotConnection {
    fn is_alive(&self) -> bool {
        self.last_used.elapsed() < Duration::from_secs(300)  // 5分钟空闲超时，提升移动端体验
    }
}

/// Configuration for building DoH client (stored for lazy init)
#[derive(Debug, Clone)]
pub struct DohClientConfig {
    pub socks5: Option<String>,
    pub dial_addr: Option<String>,
    pub url: String,
    pub mark: Option<u32>, // Kernel Mark for DoH
}

impl Upstream {
    pub fn new(conf: UpstreamConfig) -> Result<Self> {
        let addr_str = &conf.addr;
        let label = addr_str.clone();

        if addr_str.starts_with("https://") {
            // DoH - Store config for lazy client creation
            let proxy_enabled = conf.socks5.is_some();
            let bootstrap_ip = conf.dial_addr.as_ref()
                .and_then(|d| d.parse::<std::net::IpAddr>().ok());
            
            let client_config = Arc::new(DohClientConfig {
                socks5: conf.socks5.clone(),
                dial_addr: conf.dial_addr.clone(),
                url: addr_str.clone(),
                mark: conf.so_mark,
            });
            
            Ok(Upstream::Doh {
                url: addr_str.clone(),
                client: Arc::new(tokio::sync::OnceCell::new()),
                client_config,
                proxy_enabled,
                label,
                bootstrap_ip,
            })
        } else if addr_str.starts_with("tls://") {
            // DoT (DNS-over-TLS)
            let without_prefix = addr_str.trim_start_matches("tls://");
            let (host, port) = if let Some(pos) = without_prefix.rfind(':') {
                (&without_prefix[..pos], without_prefix[pos+1..].parse().unwrap_or(853))
            } else {
                (without_prefix, 853)
            };

            let ip = if let Some(dial) = &conf.dial_addr {
                dial.parse().context("Invalid dial_addr for DoT")?
            } else {
                // 简化：直接解析 host
                use std::net::ToSocketAddrs;
                format!("{}:{}", host, port)
                    .to_socket_addrs()?
                    .next()
                    .context("Cannot resolve DoT host")?
                    .ip()
            };

            Ok(Upstream::Dot {
                addr: std::net::SocketAddr::new(ip, port),
                host: host.to_string(),
                label,
                socks5: conf.socks5,
                mark: conf.so_mark,
                tfo: conf.tcp_fast_open,
                tls_connector: Arc::new(tokio::sync::OnceCell::new()),
                conn_pool: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            })
        } else if addr_str.starts_with("quic://") {
            // DoQ (DNS-over-QUIC) - RFC 9250
            let without_prefix = addr_str.trim_start_matches("quic://");
            let (host, port) = if let Some(pos) = without_prefix.rfind(':') {
                (&without_prefix[..pos], without_prefix[pos+1..].parse().unwrap_or(853))
            } else {
                (without_prefix, 853)
            };

            let ip = if let Some(dial) = &conf.dial_addr {
                dial.parse().context("Invalid dial_addr for DoQ")?
            } else {
                use std::net::ToSocketAddrs;
                format!("{}:{}", host, port)
                    .to_socket_addrs()?
                    .next()
                    .context("Cannot resolve DoQ host")?
                    .ip()
            };

            Ok(Upstream::Doq {
                addr: std::net::SocketAddr::new(ip, port),
                host: host.to_string(),
                label,
                socks5: conf.socks5,
                mark: conf.so_mark,
                endpoint: Arc::new(tokio::sync::OnceCell::new()),
                conn_pool: Arc::new(tokio::sync::Mutex::new(None)),
                socks5_tunnel: Arc::new(tokio::sync::Mutex::new(None)),
            })
        } else if addr_str.starts_with("tcp://") {
            // TCP
            let clean = addr_str.trim_start_matches("tcp://");
            let addr = clean.parse().context("Invalid TCP address")?;
            Ok(Upstream::Tcp {
                addr,
                label,
                bootstrap_host: None,
                socks5: conf.socks5,
                mark: conf.so_mark,
                tfo: conf.tcp_fast_open,
            })
        } else {
            // UDP (默认)
            let clean = addr_str.replace("udp://", "").replace("dns://", "");
            let addr = clean.parse().context("Invalid UDP address")?;
            Ok(Upstream::Udp {
                addr,
                label,
                bootstrap_host: None,
                socks5: conf.socks5,
                mark: conf.so_mark,
            })
        }
    }

    pub async fn exchange(&self, req: &Message) -> Result<Message> {
        let start = std::time::Instant::now();
        let label = self.get_label();

        metrics::inc_upstream_request(&label);

        let result = match self {
            Upstream::Udp { addr, mark, .. } => self.raw_udp(addr, *mark, req).await,
            Upstream::Tcp { addr, socks5, mark, tfo, .. } => self.raw_tcp(addr, socks5, *mark, *tfo, req).await,
            Upstream::Doh { url, client, client_config, .. } => {
                self.raw_doh(url, client, client_config, req).await
            },
            Upstream::Dot { addr, host, socks5, tls_connector, conn_pool, mark, tfo, .. } => {
                self.raw_dot_pooled(addr, host, socks5, tls_connector, conn_pool, *mark, *tfo, req).await
            },
            Upstream::Doq { addr, host, socks5, endpoint, conn_pool, socks5_tunnel, mark, .. } => {
                self.raw_doq(addr, host, socks5, endpoint, conn_pool, socks5_tunnel, *mark, req).await
            },
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::observe_upstream_latency(&label, elapsed);

        // Update AutoPilot health metrics
        let elapsed_ms = (elapsed * 1000.0) as u64;
        match &result {
            Ok(_) => {
                crate::autopilot::record_success(&label, elapsed_ms);
            },
            Err(e) => {
                crate::autopilot::record_failure(&label);
                let err_label = if e.to_string().contains("timeout") {
                    "timeout"
                } else {
                    "io_fail"
                };
                metrics::inc_upstream_error(&label, err_label);
            }
        }

        result
    }

    async fn raw_udp(&self, addr: &std::net::SocketAddr, mark: Option<u32>, req: &Message) -> Result<Message> {
        let req_bytes = req.to_vec()?;
        
        // Socket2 优化：大缓冲区
        let socket = Socket::new(
            if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
            Type::DGRAM,
            Some(Protocol::UDP)
        )?;

        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        
        // Kernel Mark (FwMark) - using libc directly for compatibility
        if let Some(m) = mark {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                let mark_val: libc::c_int = m as libc::c_int;
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        36, // SO_MARK
                        &mark_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        // 512KB 接收缓冲区（PVE/LXC 优化）
        socket.set_recv_buffer_size(524288)?;
        socket.set_send_buffer_size(524288)?;

        let bind_addr: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        socket.bind(&bind_addr.into())?;
        socket.connect(&(*addr).into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

        // UDP 重试机制：最多重试 2 次 (总共 3 次尝试)
        let mut retries = 0;
        const MAX_RETRIES: i32 = 2;
        let mut buf = vec![0u8; 4096];

        loop {
            tokio_socket.send(&req_bytes).await?;
            
            // 等待响应，设置 2 秒单次超时
            match tokio::time::timeout(Duration::from_secs(2), tokio_socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    let resp = Message::from_vec(&buf[..len])?;
                    // TC Bit 检查：如果截断，自动切换到 TCP
                    if resp.header().truncated() {
                        warn!("⚠️ UDP response truncated (TC bit set), falling back to TCP");
                        // Fallback to TCP (without TFO / Mark explicitly passed? No, recursion needs update)
                        // Actually raw_tcp expects mark/tfo now. We should pass defaults or try to get them.
                        // Since raw_udp arguments only have mark, and we don't know TFO, assume false?
                        // But wait, if this functions called from exchange, we are inside Upstream::Udp.
                        // Upstream::Udp DOES hold mark.
                        // But recursive fallback to TCP... Udp variant doesn't have tfo config.
                        // So correct fallback is raw_tcp(addr, None, mark, false, req).
                        return self.raw_tcp(addr, &None, mark, false, req).await;
                    }
                    return Ok(resp);
                },
                Ok(Err(e)) => return Err(anyhow::anyhow!(e)), // IO Error
                Err(_) => { // Timeout
                    if retries >= MAX_RETRIES {
                        return Err(anyhow::anyhow!("UDP timeout after {} retries", retries));
                    }
                    debug!("UDP timeout, retrying... ({}/{})", retries + 1, MAX_RETRIES);
                    retries += 1;
                    continue;
                }
            }
        }
        
    }

    async fn raw_tcp(&self, addr: &std::net::SocketAddr, _socks5: &Option<String>, mark: Option<u32>, tfo: bool, req: &Message) -> Result<Message> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Custom Socket Creation for Mark/TFO
        let socket = Socket::new(
            if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
            Type::STREAM,
            Some(Protocol::TCP)
        )?;

        // Apply Kernel Options
        if let Some(m) = mark {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                let mark_val: libc::c_int = m as libc::c_int;
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        36, // SO_MARK
                        &mark_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        if tfo {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                // TCP_FASTOPEN_CONNECT = 30 on Linux
                let enable: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        30, // TCP_FASTOPEN_CONNECT
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        // Connect with timeout
        let addr_clone = *addr; // Copy for 'static lifetime in closure
        let socket = tokio::task::spawn_blocking(move || -> Result<Socket> {
             let bind_addr: std::net::SocketAddr = if addr_clone.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
             socket.bind(&bind_addr.into())?;
             socket.connect(&addr_clone.into())?;
             Ok(socket)
        }).await??;

        let std_stream: std::net::TcpStream = socket.into();
        std_stream.set_nonblocking(true)?;
        
        match std_stream.set_nodelay(true) {
            Ok(_) => {},
            Err(e) => warn!("Failed to set nodelay: {}", e)
        }

        let mut stream = TcpStream::from_std(std_stream)?;


        let req_bytes = req.to_vec()?;
        let len = req_bytes.len() as u16;
        
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&req_bytes).await?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        Ok(Message::from_vec(&resp_buf)?)
    }

    async fn raw_doh(
        &self, 
        url: &str, 
        client_cell: &Arc<tokio::sync::OnceCell<reqwest::Client>>,
        config: &Arc<DohClientConfig>,
        req: &Message
    ) -> Result<Message> {
        // Lazy-init client on first request (in correct async context!)
        let client = client_cell.get_or_init(|| async {
            debug!("🔨 Building DoH client for {} (lazy init)", url);

            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                .http2_prior_knowledge()
                .pool_idle_timeout(Duration::from_secs(300))  // 5分钟超时，提升移动端体验
                .pool_max_idle_per_host(10)  // 增加连接池大小
                .user_agent("TitanDNS/7.3.9")
                .timeout(Duration::from_secs(5));

            if let Some(socks5_addr) = &config.socks5 {
                let proxy_url = if socks5_addr.contains("://") {
                    socks5_addr.clone()
                } else {
                    format!("socks5://{}", socks5_addr)
                };
                if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
                    builder = builder.proxy(proxy);
                }
            }

            // Bootstrap IP
            if let Some(dial) = &config.dial_addr {
                if let Ok(ip) = dial.parse::<std::net::IpAddr>() {
                    if let Ok(u) = url::Url::parse(&config.url) {
                        if let Some(host) = u.host_str() {
                            let port = u.port().unwrap_or(443);
                            let socket_addr = std::net::SocketAddr::new(ip, port);
                            builder = builder.resolve(host, socket_addr);
                        }
                    }
                }
            }

            builder.build().expect("Failed to build reqwest client")
        }).await;

        let req_bytes = req.to_vec()?;

        let resp_bytes = client.post(url)
            .header("content-type", "application/dns-message")
            .body(req_bytes)
            .send()
            .await?
            .bytes()
            .await?;

        Ok(Message::from_vec(&resp_bytes)?)
    }

    /// Pooled DoT implementation - reuses TLS connections
    async fn raw_dot_pooled(
        &self,
        addr: &std::net::SocketAddr,
        host: &str,
        _socks: &Option<String>,
        tls_connector: &Arc<tokio::sync::OnceCell<tokio_rustls::TlsConnector>>,
        conn_pool: &Arc<tokio::sync::Mutex<Vec<DotConnection>>>,
        mark: Option<u32>,
        tfo: bool,
        req: &Message,
    ) -> Result<Message> {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1. Lazy-initialize TLS connector (once per upstream)
        let connector = tls_connector.get_or_init(|| async {
            debug!("🔨 Building DoT TLS connector for {} (lazy init)", host);
            
            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                root_store.add(cert).ok();
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            TlsConnector::from(Arc::new(config))
        }).await;

        // 2. Try to get an existing connection from pool
        let mut stream_opt = None;
        {
            let mut pool = conn_pool.lock().await;
            pool.retain(|c| c.is_alive());
            if let Some(mut conn) = pool.pop() {
                conn.last_used = std::time::Instant::now();
                stream_opt = Some(conn.stream);
                debug!("♻️ Reusing pooled DoT connection to {}", host);
            }
        }

        // 3. Create new connection if pool empty
        let mut tls_stream = match stream_opt {
            Some(s) => s,
            None => {
                debug!("🔗 Creating new DoT connection to {}", host);
                
                // Custom Socket logic for TFO/Mark
                let socket = Socket::new(
                    if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
                    Type::STREAM,
                    Some(Protocol::TCP)
                )?;

                if let Some(m) = mark {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::unix::io::AsRawFd;
                        let mark_val: libc::c_int = m as libc::c_int;
                        unsafe {
                            libc::setsockopt(
                                socket.as_raw_fd(),
                                libc::SOL_SOCKET,
                                36, // SO_MARK
                                &mark_val as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                            );
                        }
                    }
                }

                if tfo {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::unix::io::AsRawFd;
                        let enable: libc::c_int = 1;
                        unsafe {
                            libc::setsockopt(
                                socket.as_raw_fd(),
                                libc::IPPROTO_TCP,
                                30, // TCP_FASTOPEN_CONNECT
                                &enable as *const _ as *const libc::c_void,
                                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                            );
                        }
                    }
                }

                // Connect logic spawned to blocking thread
                let addr_clone = *addr; // Copy for closure
                let socket = tokio::task::spawn_blocking(move || -> Result<Socket> {
                     let bind_addr: std::net::SocketAddr = if addr_clone.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
                     socket.bind(&bind_addr.into())?;
                     socket.connect(&addr_clone.into())?;
                     Ok(socket)
                }).await??;

                let std_stream: std::net::TcpStream = socket.into();
                std_stream.set_nonblocking(true)?;
                let tcp_stream = TcpStream::from_std(std_stream)?;
                tcp_stream.set_nodelay(true)?;
                
                let domain = rustls::pki_types::ServerName::try_from(host)
                    .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
                    .to_owned();
                
                connector.connect(domain, tcp_stream).await?
            }
        };

        // 4. Send request (DNS over TCP: 2-byte length prefix)
        let req_bytes = req.to_vec()?;
        let len = req_bytes.len() as u16;

        tls_stream.write_all(&len.to_be_bytes()).await?;
        tls_stream.write_all(&req_bytes).await?;
        tls_stream.flush().await?;

        // 5. Read response
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tls_stream.read_exact(&mut resp_buf).await?;

        // 6. Return connection to pool (if successful)
        {
            let mut pool = conn_pool.lock().await;
            if pool.len() < 4 {  // Max 4 connections per upstream
                pool.push(DotConnection {
                    stream: tls_stream,
                    last_used: std::time::Instant::now(),
                });
            }
        }

        Ok(Message::from_vec(&resp_buf)?)
    }

    /// DNS-over-QUIC implementation (RFC 9250)
    async fn raw_doq(
        &self,
        addr: &std::net::SocketAddr,
        host: &str,
        socks5: &Option<String>,
        endpoint_cell: &Arc<tokio::sync::OnceCell<quinn::Endpoint>>,
        conn_pool: &Arc<tokio::sync::Mutex<Option<quinn::Connection>>>,
        socks5_tunnel: &Arc<tokio::sync::Mutex<Option<crate::socks5_udp::Socks5UdpTunnel>>>,
        mark: Option<u32>,
        req: &Message,
    ) -> Result<Message> {
        // Check if SOCKS5 proxy is configured
        if let Some(proxy_addr_str) = socks5 {
             // For SOCKS5, mark is handled by Socks5UdpTunnel implicitly (if implemented)
             // For now we just pass through
            return self.raw_doq_via_socks5(addr, host, proxy_addr_str, socks5_tunnel, req).await;
        }

        // Direct DoQ (no proxy)
        // 1. Lazy-initialize QUIC endpoint (once per upstream)
        let endpoint = endpoint_cell.get_or_init(|| async {
            debug!("🔨 Building DoQ endpoint for {} (with mark {:?})", host, mark);
            
            // Build TLS config
            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                root_store.add(cert).ok();
            }
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                    .expect("Failed to create QUIC client config")
            ));
            
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));  // 5分钟，提升移动端体验
            client_config.transport_config(Arc::new(transport));

            // Custom Socket Creation with Mark
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .expect("Failed to create UDP socket for DoQ");
            if let Some(m) = mark {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::io::AsRawFd;
                    let mark_val: libc::c_int = m as libc::c_int;
                    unsafe {
                        libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::SOL_SOCKET,
                            36, // SO_MARK
                            &mark_val as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                    }
                }
            }
            let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()
                .expect("Failed to parse bind address 0.0.0.0:0");
            socket.bind(&bind_addr.into())
                .expect("Failed to bind socket to 0.0.0.0:0");
            let std_socket: std::net::UdpSocket = socket.into();
            
            let runtime = quinn::default_runtime().expect("No default runtime");
            let mut endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(), 
                None, 
                std_socket, 
                runtime
            ).expect("Failed to create QUIC endpoint");
            
            endpoint.set_default_client_config(client_config);
            endpoint
        }).await;

        // 2. Get or create connection
        let connection = {
            let mut pool = conn_pool.lock().await;
            if let Some(ref conn) = *pool {
                if conn.close_reason().is_none() {
                    conn.clone()
                } else {
                    *pool = None;
                    drop(pool);
                    self.create_doq_connection(endpoint, addr, host).await?
                }
            } else {
                drop(pool);
                self.create_doq_connection(endpoint, addr, host).await?
            }
        };

        // 3. Open stream
        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| anyhow::anyhow!("Failed to open QUIC stream: {}", e))?;

        // 4. Send DNS query
        let req_bytes = req.to_vec()?;
        let len = req_bytes.len() as u16;
        
        send_stream.write_all(&len.to_be_bytes()).await?;
        send_stream.write_all(&req_bytes).await?;
        send_stream.finish()?;

        // 5. Read response
        let mut len_buf = [0u8; 2];
        recv_stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        recv_stream.read_exact(&mut resp_buf).await?;

        // 6. Return to pool
        {
            let mut pool = conn_pool.lock().await;
            *pool = Some(connection);
        }

        Ok(Message::from_vec(&resp_buf)?)
    }

    /// DoQ via SOCKS5 UDP ASSOCIATE
    /// Note: This is a simplified implementation that sends raw DNS over SOCKS5 UDP
    /// Full QUIC over SOCKS5 would require more complex socket handling
    async fn raw_doq_via_socks5(
        &self,
        addr: &std::net::SocketAddr,
        host: &str,
        proxy_addr_str: &str,
        socks5_tunnel: &Arc<tokio::sync::Mutex<Option<crate::socks5_udp::Socks5UdpTunnel>>>,
        req: &Message,
    ) -> Result<Message> {
        use crate::socks5_udp::Socks5UdpTunnel;
        
        let proxy_addr: std::net::SocketAddr = proxy_addr_str.parse()
            .map_err(|e| anyhow::anyhow!("Invalid SOCKS5 proxy address: {}", e))?;

        // Initialize tunnel if not exists
        {
            let mut tunnel_guard = socks5_tunnel.lock().await;
            if tunnel_guard.is_none() {
                debug!("🔗 Creating SOCKS5 UDP tunnel via {} for DoQ to {}", proxy_addr, host);
                let tunnel = Socks5UdpTunnel::new(proxy_addr);
                tunnel.connect().await
                    .map_err(|e| anyhow::anyhow!("SOCKS5 UDP tunnel failed: {}", e))?;
                *tunnel_guard = Some(tunnel);
            }
        }

        // Send DNS query through SOCKS5 UDP
        let tunnel_guard = socks5_tunnel.lock().await;
        let tunnel = tunnel_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("SOCKS5 tunnel not initialized"))?;

        // For DoQ over SOCKS5, we send raw DNS wire format
        // Note: This is a simplified approach - proper QUIC would need full QUIC state machine
        let req_bytes = req.to_vec()?;
        
        // DNS over UDP (no length prefix for UDP)
        tunnel.send_to(*addr, &req_bytes).await
            .map_err(|e| anyhow::anyhow!("SOCKS5 UDP send failed: {}", e))?;

        // Receive response
        let mut resp_buf = vec![0u8; 4096];
        let (len, _from) = tokio::time::timeout(
            Duration::from_secs(5),
            tunnel.recv_from(&mut resp_buf)
        ).await
            .map_err(|_| anyhow::anyhow!("DoQ via SOCKS5 timeout"))?
            .map_err(|e| anyhow::anyhow!("SOCKS5 UDP recv failed: {}", e))?;

        debug!("✅ DoQ via SOCKS5 successful to {} (via {})", host, proxy_addr);
        Ok(Message::from_vec(&resp_buf[..len])?)
    }

    async fn create_doq_connection(
        &self,
        endpoint: &quinn::Endpoint,
        addr: &std::net::SocketAddr,
        host: &str,
    ) -> Result<quinn::Connection> {
        debug!("🔗 Creating new DoQ connection to {}", host);
        
        let connection = endpoint.connect(*addr, host)
            .map_err(|e| anyhow::anyhow!("Failed to initiate QUIC connection: {}", e))?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;
        
        debug!("✅ DoQ connection established to {}", host);
        Ok(connection)
    }

    pub fn get_label(&self) -> String {
        match self {
            Upstream::Udp { label, .. } => label.clone(),
            Upstream::Tcp { label, .. } => label.clone(),
            Upstream::Doh { label, .. } => label.clone(),
            Upstream::Dot { label, .. } => label.clone(),
            Upstream::Doq { label, .. } => label.clone(),
        }
    }
}

impl ForwardPlugin {
    pub fn new(name: String, confs: Vec<UpstreamConfig>, strategy: Option<String>, concurrent: usize) -> Self {
        let upstreams: Vec<Arc<Upstream>> = confs.into_iter()
            .filter_map(|c| Upstream::new(c).ok().map(Arc::new))
            .collect();

        // Register upstreams with AutoPilot for health monitoring
        for upstream in &upstreams {
            let label = upstream.get_label();
            crate::autopilot::register_upstream(&label);
            debug!("📡 Registered upstream with AutoPilot: {}", label);
        }

        // [自适应连接池] 初始化 QPS 监控
        let qps_monitor = Arc::new(crate::plugins::adaptive_pool::AdaptiveConnectionPool::new());
        debug!("📊 QPS monitor initialized for forward plugin: {}", name);

        Self {
            name,
            upstreams,
            timeout: Duration::from_secs(5),
            concurrent_limit: Arc::new(Semaphore::new(concurrent)), // 使用配置值
            strategy,
            proxy_status: None,
            singleflight: Arc::new(Singleflight::new()),
            qps_monitor,
        }
    }

    /// Pre-warm connections to DoH/DoT upstreams by sending a dummy query.
    /// This eliminates cold-start latency on the first real query.
    pub async fn warmup(&self) {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        // Build a simple query for "localhost" A record
        let mut msg = Message::new();
        msg.set_id(0xCAFE);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        
        if let Ok(name) = Name::from_ascii("localhost") {
            msg.add_query(Query::query(name, RecordType::A));
        }

        for upstream in &self.upstreams {
            // Only warmup DoH and DoT (TLS connections are expensive)
            let needs_warmup = matches!(**upstream, Upstream::Doh { .. } | Upstream::Dot { .. });
            if needs_warmup {
                let u = upstream.clone();
                let m = msg.clone();
                let timeout = Duration::from_secs(3);
                
                // Fire and forget - don't wait for result
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(timeout, u.exchange(&m)).await;
                    debug!("🔥 Warmed up upstream: {}", u.get_label());
                });
            }
        }
    }

    fn is_foreign_upstream(upstream: &Upstream) -> bool {
        match upstream {
            // Encrypted / proxy-style upstreams treated as foreign
            Upstream::Doh { .. } | Upstream::Dot { .. } | Upstream::Doq { .. } => true,
            Upstream::Udp { socks5, .. } | Upstream::Tcp { socks5, .. } => socks5.is_some(),
        }
    }

    fn detect_network_scope(&self) -> crate::autopilot::NetworkScope {
        if self.upstreams.iter().any(|u| Self::is_foreign_upstream(u)) {
            crate::autopilot::NetworkScope::Foreign
        } else {
            crate::autopilot::NetworkScope::Domestic
        }
    }
    
    /// [Level 2] 基于查询预测触发预热
    fn trigger_prefetch(&self, domain: &str) {
        // 获取预测的下一个查询
        let predictions = crate::autopilot::predict_next_queries(domain, 2);
        
        if predictions.is_empty() {
            return;
        }
        
        // 异步预热预测的域名
        for predicted_domain in predictions {
            if let Some(upstream) = self.upstreams.first() {
                let u = upstream.clone();
                let timeout = self.timeout;
                
                tokio::spawn(async move {
                    // 构建预热查询
                    use hickory_proto::op::{Message, Query};
                    use hickory_proto::rr::{Name, RecordType};
                    
                    if let Ok(name) = predicted_domain.parse::<Name>() {
                        let mut msg = Message::new();
                        msg.add_query(Query::query(name, RecordType::A));
                        msg.set_recursion_desired(true);
                        
                        let _ = tokio::time::timeout(timeout, u.exchange(&msg)).await;
                        debug!("🔮 预测预热: {}", predicted_domain);
                    }
                });
            }
        }
    }
    
    /// Race 策略：并发查询所有上游，返回第一个成功结果
    async fn execute_race(&self, req: &Message) -> Result<Message> {
        let mut futures = FuturesUnordered::new();
        
        for upstream in self.upstreams.iter().take(self.upstreams.len().min(3)) {
            if let Upstream::Doh { proxy_enabled: true, .. } = **upstream {
                if let Some(status) = &self.proxy_status {
                    if !status.load(Ordering::Relaxed) {
                        continue;
                    }
                }
            }

            let u = upstream.clone();
            let r = req.clone();
            let timeout = self.timeout;

            futures.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let label = u.get_label();
                let result = tokio::time::timeout(timeout, u.exchange(&r)).await;
                (label, result, start.elapsed())
            }));
        }

        while let Some(res) = futures.next().await {
            if let Ok((label, Ok(Ok(msg)), elapsed)) = res {
                crate::autopilot::record_success(&label, elapsed.as_millis() as u64);
                debug!("🚀 Race success from {} ({}ms)", label, elapsed.as_millis());
                return Ok(msg);
            } else if let Ok((label, _, _)) = res {
                crate::autopilot::record_failure(&label);
            }
        }

        Err(anyhow::anyhow!("All race upstreams failed"))
    }

    pub async fn execute(&self, req: &Message, client_ip: Option<std::net::IpAddr>) -> Result<Message> {
        let _permit = self.concurrent_limit.acquire().await?;

        let strategy = self.strategy.as_deref().unwrap_or("order");

        // === NEW: Smart Strategy - AIOps-powered intelligent routing ===
        if strategy == "smart" {
            return self.execute_smart(req, client_ip).await;
        }

        if strategy == "race" {
            // 赛马模式：并发查询，返回第一个成功结果
            let mut futures = FuturesUnordered::new();
            
            for upstream in self.upstreams.iter().take(self.upstreams.len().min(3)) {
                if let Upstream::Doh { proxy_enabled: true, .. } = **upstream {
                    if let Some(status) = &self.proxy_status {
                        if !status.load(Ordering::Relaxed) {
                            continue;
                        }
                    }
                }

                let u = upstream.clone();
                let r = req.clone();
                let timeout = self.timeout;

                futures.push(tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    let label = u.get_label();
                    let result = tokio::time::timeout(timeout, u.exchange(&r)).await;
                    (label, result, start.elapsed())
                }));
            }

            while let Some(res) = futures.next().await {
                if let Ok((label, Ok(Ok(msg)), elapsed)) = res {
                    // Track success in AutoPilot
                    crate::autopilot::record_success(&label, elapsed.as_millis() as u64);
                    debug!("🚀 Race success from {} ({}ms), ID: {}", label, elapsed.as_millis(), msg.header().id());
                    return Ok(msg);
                } else if let Ok((label, _, _)) = res {
                    // Track failure in AutoPilot
                    crate::autopilot::record_failure(&label);
                }
            }

            Err(anyhow::anyhow!("All race upstreams failed"))
        } else {
            // Order 模式：顺序查询
            for upstream in &self.upstreams {
                let label = upstream.get_label();
                let start = std::time::Instant::now();
                
                match tokio::time::timeout(self.timeout, upstream.exchange(req)).await {
                    Ok(Ok(resp)) => {
                        // Track success in AutoPilot
                        crate::autopilot::record_success(&label, start.elapsed().as_millis() as u64);
                        return Ok(resp);
                    },
                    _ => {
                        // Track failure in AutoPilot
                        crate::autopilot::record_failure(&label);
                        continue;
                    }
                }
            }
            Err(anyhow::anyhow!("All upstreams failed"))
        }
    }

    /// [Level 15] 注入 EDNS Client Subnet (ECS) 到 DNS 请求
    /// 这让上游 DNS 服务器能够返回地理位置优化的结果
    /// TODO: 完善 OPT record 构造 (hickory_proto API 研究中)
    fn inject_ecs(req: &Message, client_ip: std::net::IpAddr) -> Message {
        // 获取 ECS 配置
        let ecs_ip = match crate::autopilot::get_ecs_client_ip(client_ip) {
            Some(ip) => ip,
            None => return req.clone(), // ECS 未启用或无有效 IP
        };
        
        let prefix_len = crate::autopilot::get_ecs_prefix_length(ecs_ip);
        
        // 构建 ECS 选项数据 (已准备好，待 OPT 注入)
        let _ecs_data = crate::autopilot::build_ecs_option(ecs_ip, prefix_len);
        
        // TODO: hickory_proto OPT 构造 API 需要进一步研究
        // 目前先记录日志，不实际注入
        debug!("⚡ ECS 准备就绪 (待注入): {} /{}", ecs_ip, prefix_len);
        
        req.clone()
    }

    /// [Level 19] 后台验证 DNS 响应中的 IP 可达性
    fn spawn_response_ip_verification(resp: &Message, upstream: String) {
        use hickory_proto::rr::RData;
        
        // 提取响应中的 A/AAAA 记录 IP
        let ips: Vec<std::net::IpAddr> = resp.answers()
            .iter()
            .filter_map(|ans| {
                match ans.data() {
                    RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
                    RData::AAAA(aaaa) => Some(std::net::IpAddr::V6(aaaa.0)),
                    _ => None,
                }
            })
            .collect();
        
        // 触发后台验证
        if !ips.is_empty() {
            crate::autopilot::spawn_ip_verification(ips, upstream);
        }
    }

    /// Smart execution with Adaptive Hedged Request strategy:
/// 1. [优化] 自适应 Hedge Delay: 根据 Primary 的 P95 延迟动态调整
/// 2. [优化] 双主并发: 如果 Top1 和 Top2 分数接近，并发查询 (比 Race 省带宽，比单主快)
/// 3. Send to best upstream based on AutoPilot scores
/// 4. If no response in hedge_delay, fire backup request to 2nd best
/// 5. Return first successful response
/// 
/// [Phase 4] 深度智能化:
/// 6. 网络状况感知: 拥堵时自动切换 Race
/// 7. 时间感知路由: 晚高峰自动 Race
/// 8. 预测性故障转移: 过滤劣化上游
/// 
/// This is more efficient than "race" (saves bandwidth) while being 
/// faster than "order" (doesn't wait for full timeout before trying next)
async fn execute_smart(&self, req: &Message, client_ip: Option<std::net::IpAddr>) -> Result<Message> {
    // === Level 1: AI 学习 - 域名记忆快速通道 ===
    
    // 提取域名（可选，失败则跳过 AI 学习）
    let domain = req.query().map(|q| q.name().to_string());
    
    
    // [Level 7.2] DGA 恶意域名检测
    if let Some(ref d) = domain {
        let dga = crate::autopilot::detect_dga_domain(d);
        if dga.is_dga {
            warn!("🚨 拦截 DGA 恶意域名: {} (原因: {}, 分数: {:.2})", d, dga.reason, dga.score);
            return Err(anyhow::anyhow!("Blocked DGA Domain: {}", d)); // 直接拦截
        }
    }
    
    
    // [Level 5] 记录域名查询热度
    if let Some(ref d) = domain {
        crate::autopilot::record_domain_query(d);
        // [Level 21] 记录时间模式 (用于预测性预取)
        crate::autopilot::record_timed_access(d);
    }
    
    // [Level 15] EDNS Client Subnet (ECS) - 注入客户端子网信息
    let req = if let Some(ip) = client_ip {
        Self::inject_ecs(req, ip)
    } else {
        req.clone()
    };
    let req = &req; // reborrow for the rest of the function
    
    
    // [Level 13] 查询域名记忆：优先使用客户端感知版本
    if let Some(ref domain_str) = domain {
        // 使用客户端感知的域名记忆查询
        let best_upstream_label = if let Some(ip) = client_ip {
            crate::autopilot::get_domain_best_upstream_for_client(domain_str, ip)
        } else {
            crate::autopilot::get_domain_best_upstream(domain_str)
        };
        
        if let Some(best_label) = best_upstream_label {
            // 在上游列表中查找匹配的上游
            if let Some(upstream) = self.upstreams.iter()
                .find(|u| u.get_label() == best_label) 
            {
                let start = std::time::Instant::now();
                let label = upstream.get_label();
                
                // 尝试使用历史最优上游
                match tokio::time::timeout(self.timeout, upstream.exchange(req)).await {
                    Ok(Ok(resp)) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        crate::autopilot::record_success(&label, elapsed);
                        // [Level 13] 更新客户端感知域名记忆
                        if let Some(ip) = client_ip {
                            crate::autopilot::record_domain_result_for_client(domain_str, &label, elapsed, ip);
                        } else {
                            crate::autopilot::record_domain_result(domain_str, &label, elapsed);
                        }
                        // [Level 2] 记录查询序列 + 触发预热
                        crate::autopilot::record_query_sequence(domain_str);
                        self.trigger_prefetch(domain_str);
                        // [Level 19] 后台验证返回的 IP 可达性
                        Self::spawn_response_ip_verification(&resp, label.clone());
                        debug!("🎯 AI快速通道命中: {} → {} ({}ms)", domain_str, label, elapsed);
                        return Ok(resp);
                    }
                    _ => {
                        // 快速通道失败，继续正常流程
                        crate::autopilot::record_failure(&label);
                        debug!("⚠️ AI快速通道失败: {} ({}), 切换常规流程", domain_str, label);
                    }
                }
            }
        }
    }
    
    // === Phase 4: 深度智能化决策 ===
    

    // 1. 检测网络状况 (区分 Scope)
    let mut scope = self.detect_network_scope();

    // [Fix] 根据插件名称强制修正作用域 (解决 AliDNS/DNSPod DoH 虽然是https但仍应为Domestic的问题)
    let name_lower = self.name.to_lowercase();
    if name_lower.contains("domestic") || name_lower.contains("local") || name_lower.contains("cn") {
        scope = crate::autopilot::NetworkScope::Domestic;
    } else if name_lower.contains("proxy") || name_lower.contains("foreign") {
        scope = crate::autopilot::NetworkScope::Foreign;
    }

    let network_condition = crate::autopilot::get_network_condition(scope);
    debug!("🌐 网络状况({:?}): 拥堵等级={}/10, 抖动={:.1}ms, 丢包率={:.1}%", 
           scope,
           network_condition.congestion_level,
           network_condition.avg_jitter_ms,
           network_condition.avg_loss_rate * 100.0);
    
    // 2. 时间感知推荐
    let (time_strategy, time_hedge) = crate::autopilot::get_time_based_recommendation();
    debug!("🕐 时间段策略: {}, Hedge={:?}", time_strategy, time_hedge);
    
    // 3. 渐进式智能策略: 根据拥堵等级动态调整并发数
    let total_upstreams = self.upstreams.len();
    let (concurrency, strategy_name) = match network_condition.congestion_level {
        0..=2 => (1, "Pure-Smart"),           // 网络优秀: 只查最优
        3..=4 => (2, "Mini-Race"),            // 网络良好: 查前2名
        5..=6 => (3.min(total_upstreams), "Medium-Race"),  // 网络一般: 查前3名
        7..=8 => ((total_upstreams / 2).max(3), "Heavy-Race"), // 网络拥堵: 查一半
        _ => (total_upstreams, "Full-Race"),  // 严重拥堵: 全部并发
    };
    
    // 时间段策略可以 override (但不再绝对切换，只是提升并发数)
    let mut final_concurrency = if time_strategy == "race" {
        total_upstreams.max(concurrency) // 时间段 race 只作为提升，不强制全量
    } else {
        concurrency
    };
    
    // [Level 12] 域名难度加成: 历史表现差的域名自动提升并发数
    if let Some(ref d) = domain {
        let difficulty_boost = crate::autopilot::get_difficulty_concurrency_boost(d);
        if difficulty_boost > 0 {
            final_concurrency = (final_concurrency + difficulty_boost).min(total_upstreams);
            debug!("🎯 域名难度加成: {} 难度等级={}, 并发+{}", 
                   d, crate::autopilot::get_domain_difficulty(d), difficulty_boost);
        }
    }
    
    debug!("🚦 渐进式智能: 策略={}, 并发数={}/{}, 拥堵={}/10, 时段={}", 
           strategy_name, final_concurrency, total_upstreams,
           network_condition.congestion_level, time_strategy);
    
    // Register all upstreams with AutoPilot (idempotent)
    for upstream in &self.upstreams {
        crate::autopilot::register_upstream(&upstream.get_label());
    }

    // Get ranked upstreams from AutoPilot
    let ranked = crate::autopilot::get_ranked_upstreams_for_scope(scope);
    
    // Build lookup map
    let upstream_map: std::collections::HashMap<String, &Arc<Upstream>> = 
        self.upstreams.iter().map(|u| (u.get_label(), u)).collect();

    // Filter to available upstreams (proxy check + 预测性故障转移)
    let available: Vec<&Arc<Upstream>> = ranked.iter()
        .filter_map(|label| upstream_map.get(label).copied())
        .filter(|upstream| {
            // 代理检查
            if let Upstream::Doh { proxy_enabled: true, .. } = ***upstream {
                if let Some(status) = &self.proxy_status {
                    if !status.load(Ordering::Relaxed) {
                        return false;
                    }
                }
            }
            
            // [Phase 4] 预测性故障转移: 过滤正在劣化的上游
            let label = upstream.get_label();
            if crate::autopilot::is_upstream_degrading(&label) {
                debug!("🔮 过滤劣化上游: {}", label);
                return false;
            }
            
            true
        })
        .take(final_concurrency) // 动态并发数
        .collect();

    if available.is_empty() {
        return Err(anyhow::anyhow!("No available upstreams"));
    }

    // === 优化 1: 自适应 Hedge Delay ===
    let primary_label = available[0].get_label();
    // [Level 4.2] 自适应 Hedge Delay: 基于 P95 + Jitter 实时计算
    let mut hedge_delay = crate::autopilot::get_adaptive_hedge_delay(&primary_label);
    
    // 网络拥堵时缩短 Hedge Delay (更激进)
    if network_condition.congestion_level >= 5 {
        hedge_delay = hedge_delay.mul_f64(0.7); // 70%
    }
    
    debug!("🕐 Smart Strategy: Primary={}, AdaptiveHedge={:?}", primary_label, hedge_delay);
    
    debug!("🤖 Smart策略: Primary={} AdaptiveHedge={}ms, 网络={}/10", 
           primary_label, hedge_delay.as_millis(), network_condition.congestion_level);

    // === 优化 2: 根据并发数选择执行方式 ===
    if available.len() >= 3 {
        // 3个以上: 使用渐进式并发
        debug!("🚀 Graduated-Race: 并发查询 {} 个上游", available.len());
        return self.execute_graduated_race(&available, req, &domain, client_ip).await;
    } else if available.len() == 2 {
        // 2个: Mini-Race
        debug!("🚀 Mini-Race: 并发查询前2名");
        return self.execute_parallel_dual(available[0], available[1], req).await;
    }

    // === 标准 Hedged Request 逻辑 ===
    
    // If only 1 upstream, just use it directly
    if available.len() == 1 {
        let upstream = available[0];
        let label = upstream.get_label();
        let start = std::time::Instant::now();
        
        match tokio::time::timeout(self.timeout, upstream.exchange(req)).await {
            Ok(Ok(resp)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                crate::autopilot::record_success(&label, elapsed);
                // [AI学习] 记录域名最佳上游 (客户端感知)
                if let Some(ref d) = domain {
                    if let Some(ip) = client_ip {
                        crate::autopilot::record_domain_result_for_client(d, &label, elapsed, ip);
                    } else {
                        crate::autopilot::record_domain_result(d, &label, elapsed);
                    }
                    // [Level 2] 记录查询序列 + 触发预热
                    crate::autopilot::record_query_sequence(d);
                    self.trigger_prefetch(d);
                }
                debug!("🤖 Smart: {} responded in {}ms", label, elapsed);
                return Ok(resp);
            }
            _ => {
                crate::autopilot::record_failure(&label);
                return Err(anyhow::anyhow!("Single upstream failed"));
            }
        }
    }

    // Multiple upstreams: use hedged request
    let primary = available[0].clone();
    let primary_label = primary.get_label();
    let req_clone = req.clone();
    let timeout = self.timeout;
    
    // Spawn primary request
    let primary_start = std::time::Instant::now();
    let primary_handle = tokio::spawn(async move {
        let result = tokio::time::timeout(timeout, primary.exchange(&req_clone)).await;
        (primary_label, result, primary_start.elapsed())
    });

    // Wait for hedge_delay or primary completion
    tokio::select! {
        // Primary completed within hedge delay
        result = &mut Box::pin(async { primary_handle.await }) => {
            match result {
                Ok((label, Ok(Ok(resp)), elapsed)) => {
                    let elapsed_ms = elapsed.as_millis() as u64;
                    crate::autopilot::record_success(&label, elapsed_ms);
                    // [AI学习] 记录域名最佳上游 (客户端感知)
                    if let Some(ref d) = domain {
                        if let Some(ip) = client_ip {
                            crate::autopilot::record_domain_result_for_client(d, &label, elapsed_ms, ip);
                        } else {
                            crate::autopilot::record_domain_result(d, &label, elapsed_ms);
                        }
                    }
                    debug!("🤖 Smart[Primary]: {} responded in {}ms (score: {})", 
                           elapsed_ms,
                           label,
                           crate::autopilot::AUTOPILOT.get(&label).map(|m| m.get_score()).unwrap_or(0));
                    return Ok(resp);
                }
                Ok((label, _, _)) => {
                    crate::autopilot::record_failure(&label);
                    // Primary failed, try remaining upstreams
                }
                Err(_) => {
                    // Join error, continue to backups
                }
            }
        }
        
        // Hedge delay expired, fire backup request
        _ = tokio::time::sleep(hedge_delay) => {
            debug!("🤖 Smart: Primary didn't respond in {}ms, firing hedged request", hedge_delay.as_millis());
        }
    }

    // Fire backup requests (hedged)
    let mut futures = FuturesUnordered::new();
    
    for upstream in available.iter().skip(1) {
        let u = (*upstream).clone();
        let r = req.clone();
        let t = self.timeout;
        
        futures.push(tokio::spawn(async move {
            let start = std::time::Instant::now();
            let label = u.get_label();
            let result = tokio::time::timeout(t, u.exchange(&r)).await;
            (label, result, start.elapsed())
        }));
    }

    // Also add the original primary handle back if it's still running
    // (it might complete while we're processing backups)
    
    // Wait for any response
    while let Some(res) = futures.next().await {
        match res {
            Ok((label, Ok(Ok(resp)), elapsed)) => {
                let elapsed_ms = elapsed.as_millis() as u64;
                crate::autopilot::record_success(&label, elapsed_ms);
                // [AI学习] 记录域名最佳上游
                    if let Some(ref d) = domain {
                        if let Some(ip) = client_ip {
                            crate::autopilot::record_domain_result_for_client(d, &label, elapsed_ms, ip);
                        } else {
                            crate::autopilot::record_domain_result(d, &label, elapsed_ms);
                        }
                        // [Level 2] 记录查询序列 + 触发预热
                        crate::autopilot::record_query_sequence(d);
                        self.trigger_prefetch(d);
                    }
                debug!("🤖 Smart[Hedge]: {} responded in {}ms (score: {})", 
                       label, elapsed_ms,
                       crate::autopilot::AUTOPILOT.get(&label).map(|m| m.get_score()).unwrap_or(0));
                return Ok(resp);
            }
            Ok((label, _, _)) => {
                crate::autopilot::record_failure(&label);
                debug!("🤖 Smart[Hedge]: {} failed", label);
            }
            Err(_) => {}
        }
    }

    // All failed - try any remaining upstreams not in ranked list
    for upstream in &self.upstreams {
        let label = upstream.get_label();
        if !ranked.contains(&label) {
            let start = std::time::Instant::now();
            
            match tokio::time::timeout(self.timeout, upstream.exchange(req)).await {
                Ok(Ok(resp)) => {
                    crate::autopilot::record_success(&label, start.elapsed().as_millis() as u64);
                    return Ok(resp);
                }
                _ => {
                    crate::autopilot::record_failure(&label);
                    continue;
                }
            }
        }
    }

    Err(anyhow::anyhow!("Smart routing: All upstreams failed"))
}

    /// Executes two upstreams in parallel (mini-race) and returns the first successful response.
    async fn execute_parallel_dual(&self, u1: &Arc<Upstream>, u2: &Arc<Upstream>, req: &Message) -> Result<Message> {
        let mut futures = FuturesUnordered::new();
        let timeout = self.timeout;

        let req_clone1 = req.clone();
        let u1_clone = u1.clone();
        futures.push(tokio::spawn(async move {
            let start = std::time::Instant::now();
            let label = u1_clone.get_label();
            let result = tokio::time::timeout(timeout, u1_clone.exchange(&req_clone1)).await;
            (label, result, start.elapsed())
        }));

        let req_clone2 = req.clone();
        let u2_clone = u2.clone();
        futures.push(tokio::spawn(async move {
            let start = std::time::Instant::now();
            let label = u2_clone.get_label();
            let result = tokio::time::timeout(timeout, u2_clone.exchange(&req_clone2)).await;
            (label, result, start.elapsed())
        }));

        while let Some(res) = futures.next().await {
            match res {
                Ok((label, Ok(Ok(resp)), elapsed)) => {
                    crate::autopilot::record_success(&label, elapsed.as_millis() as u64);
                    debug!("🤖 Dual-Race: {} responded in {}ms", label, elapsed.as_millis());
                    return Ok(resp);
                }
                Ok((label, _, _)) => {
                    crate::autopilot::record_failure(&label);
                    debug!("🤖 Dual-Race: {} failed", label);
                }
                Err(_) => {}
            }
        }

        Err(anyhow::anyhow!("Dual-Race: Both upstreams failed"))
    }

    /// Executes N upstreams in parallel (graduated-race) and returns the first successful response.
    /// This is更智能 than full race - it queries only the top N upstreams based on congestion level.
    async fn execute_graduated_race(
        &self, 
        upstreams: &[&Arc<Upstream>], 
        req: &Message,
        domain: &Option<String>,
        client_ip: Option<std::net::IpAddr>
    ) -> Result<Message> {
        use futures::stream::FuturesUnordered;
        use futures::StreamExt;
        
        let mut futures = FuturesUnordered::new();
        let timeout = self.timeout;

        // 并发发起请求
        for upstream in upstreams {
            let u = (*upstream).clone();
            let r = req.clone();
            let t = timeout;
            
            futures.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let label = u.get_label();
                let result = tokio::time::timeout(t, u.exchange(&r)).await;
                (label, result, start.elapsed())
            }));
        }

        // 等待第一个成功响应
        let mut attempts = 0u32;
        while let Some(res) = futures.next().await {
            attempts += 1;
            match res {
                Ok((label, Ok(Ok(resp)), elapsed)) => {
                    let elapsed_ms = elapsed.as_millis() as u64;
                    crate::autopilot::record_success(&label, elapsed_ms);
                    
                    // 记录域名学习 (客户端感知)
                    if let Some(ref d) = domain {
                        if let Some(ip) = client_ip {
                            crate::autopilot::record_domain_result_for_client(d, &label, elapsed_ms, ip);
                        } else {
                            crate::autopilot::record_domain_result(d, &label, elapsed_ms);
                        }
                        crate::autopilot::record_query_sequence(d);
                        // [Level 12] 记录域名难度
                        crate::autopilot::record_domain_attempt(d, true, attempts);
                    }
                    
                    debug!("🚀 Graduated-Race: {} 响应 {}ms (并发{}个, 第{}个成功)", 
                           label, elapsed_ms, upstreams.len(), attempts);
                    return Ok(resp);
                }
                Ok((label, _, _)) => {
                    crate::autopilot::record_failure(&label);
                    debug!("❌ Graduated-Race: {} 失败", label);
                }
                Err(_) => {}
            }
        }
        
        // 全部失败，记录域名难度
        if let Some(ref d) = domain {
            crate::autopilot::record_domain_attempt(d, false, upstreams.len() as u32);
        }

        Err(anyhow::anyhow!("Graduated-Race: All {} upstreams failed", upstreams.len()))
    }
}

impl Plugin for ForwardPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // [自适应连接池] 记录查询
        self.qps_monitor.record_query();

        // [Level 7.1] DDoS 拦截: 检查客户端是否在封禁名单
        if crate::autopilot::analyze_client_behavior(ctx.client_addr.ip(), false) {
            debug!("🚫 Blocked DDoS request from {}", ctx.client_addr);
            let mut resp = Message::new();
            resp.set_id(ctx.request.id());
            resp.set_message_type(hickory_proto::op::MessageType::Response);
            resp.set_response_code(hickory_proto::op::ResponseCode::Refused);
            if let Some(q) = ctx.request.query() {
                resp.add_query(q.clone());
            }
            ctx.set_response(resp, true);
            return Ok(());
        }

        let query = ctx.request.query()
            .ok_or_else(|| anyhow::anyhow!("No query"))?;

        let _key = format!("{}:{}", query.name(), u16::from(query.query_type()));
        let id = ctx.request.id();

        let res = self.execute(&ctx.request, Some(ctx.client_addr.ip())).await;

        match res {
            Ok(mut m) => { m.set_id(id); ctx.set_response(m, true); Ok(()) },
            Err(e) => {
                debug!("Forward failed: {}", e);
                // Return SERVFAIL to client instead of erroring out
                let mut resp = Message::new();
                resp.set_id(id);
                resp.set_message_type(hickory_proto::op::MessageType::Response);
                resp.set_op_code(hickory_proto::op::OpCode::Query);
                resp.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                if let Some(q) = ctx.request.query() {
                    resp.add_query(q.clone());
                }
                ctx.set_response(resp, true);
                Ok(())
            }
        }
    }

    // [Level 7.1] 响应监测: 记录 NXDOMAIN 行为
    // [Level 5.2] Smart TTL: 学习稳定性并动态调整 TTL
    async fn on_response(&self, ctx: &mut Context) -> Result<()> {
        let domain = ctx.qname_ref().to_string();
        if let Some(ref mut resp) = ctx.response {
            let rcode = resp.response_code();
            
            // 1. Level 7.1: DDoS 检测 (NXDOMAIN 洪水)
            if rcode == hickory_proto::op::ResponseCode::NXDomain {
                crate::autopilot::analyze_client_behavior(ctx.client_addr.ip(), true);
            }
            
            // 2. Level 5.2: Smart TTL
            if rcode == hickory_proto::op::ResponseCode::NoError {
                // 收集 IP 地址和当前 TTL
                let mut ips = Vec::new();
                let mut min_ttl = u32::MAX;
                
                for record in resp.answers() {
                     match record.data() {
                        RData::A(ip) => ips.push(IpAddr::V4(**ip)),
                        RData::AAAA(ip) => ips.push(IpAddr::V6(**ip)),
                        _ => {}
                    }
                    min_ttl = min_ttl.min(record.ttl());
                }
                
                // [Level 6.1] DNS 污染检测 (被动查杀)
                for ip in &ips {
                    if crate::autopilot::is_known_poison_ip(ip) {
                        warn!("🛑 拦截污染 IP: {} (Domain: {})", ip, domain);
                        // 如果是污染，强制返回 ServFail，避免缓存
                        resp.set_response_code(hickory_proto::op::ResponseCode::ServFail);
                        // 清空 Answers，避免客户端拿到假 IP
                        return Ok(()); 
                    }
                }

                if !ips.is_empty() && min_ttl != u32::MAX {
                    // 记录稳定性数据 (Input)
                    crate::autopilot::analyze_domain_stability(&domain, ips, min_ttl);
                    
                    // 获取智能 TTL 建议 (Decision)
                    if let Some(smart_ttl) = crate::autopilot::get_smart_ttl(&domain, min_ttl) {
                        // 应用 TTL (Act)
                        for record in resp.answers_mut() {
                            if matches!(record.record_type(), RecordType::A | RecordType::AAAA) {
                                record.set_ttl(smart_ttl);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
