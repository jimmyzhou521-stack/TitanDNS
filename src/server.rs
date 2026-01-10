pub mod affinity;
pub mod tls_loader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, error, debug, warn};
use anyhow::Result;
use bytes::{Bytes, BytesMut};  // Zero-copy buffer
use axum::{
    Router,
    Extension,
    extract::{State, Query, ConnectInfo},
    routing::get,
    response::IntoResponse,
    http::{StatusCode, HeaderMap, header},
    body::{Body as AxumBody, Bytes as AxumBytes},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tower::util::ServiceExt;
use tokio_rustls::TlsAcceptor;
use std::collections::HashMap;

use crate::core::context::Context;
use crate::core::plugin::Plugin;
#[allow(unused_imports)]
use crate::plugins::AnyPlugin;  // Used indirectly via HotReloadManager
use crate::stats::STATS;

#[cfg(target_os = "linux")]
pub mod batch_io;
#[cfg(target_os = "linux")]
pub mod batch_sender;
// #[cfg(target_os = "linux")]
// use crate::server::batch_io::BatchIo;
// #[cfg(target_os = "linux")]
// use crate::server::batch_sender::BatchSender;

use crate::core::metrics;

use crate::config::{SocketOpts, TlsConfig};

// Ensure socket2 types are available on all platforms
#[cfg(not(unix))]
#[allow(unused_imports)]
use socket2::{Domain, Type, Protocol as SocketProtocol};

#[cfg(unix)]
use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

// Define buffer size for Unix optimized path
const BUFFER_SIZE: usize = 4 * 1024 * 1024;

use crate::core::hot_reload::HotReloadManager;

/// The DNS Server Listener
pub struct DnsServer {
    addr: String,
    hot_reload: Arc<HotReloadManager>, // [NEW] Dynamic Plugin Manager
    entry_name: String,                // [NEW] Name of the entry point to look up
    socket_opts: SocketOpts,
    tls_config: Option<TlsConfig>,
}

impl DnsServer {
    pub fn new(addr: String, hot_reload: Arc<HotReloadManager>, entry_name: String, socket_opts: SocketOpts, tls_config: Option<TlsConfig>) -> Self {
        Self { addr, hot_reload, entry_name, socket_opts, tls_config }
    }

    /// Helper to create an optimized UDP socket
    fn create_udp_socket(addr_str: &str, opts: &SocketOpts) -> Result<UdpSocket> {
        let addr: SocketAddr = addr_str.parse()?;
        
        // --- Windows / Non-Unix Path ---
        #[cfg(not(unix))]
        {
            use socket2::{Socket, Domain, Type, Protocol};

            // Smart Buffer Sizing
            let rcv_buf = if opts.so_rcvbuf > 0 { opts.so_rcvbuf } else { 4 * 1024 * 1024 };
            let snd_buf = if opts.so_sndbuf > 0 { opts.so_sndbuf } else { 4 * 1024 * 1024 };
            
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            
            // Set buffer sizes
            if let Err(e) = socket.set_recv_buffer_size(rcv_buf) {
                warn!("Failed to set SO_RCVBUF to {}: {}", rcv_buf, e);
            } else {
                debug!("✅ SO_RCVBUF set to {} bytes", rcv_buf);
            }
            
            if let Err(e) = socket.set_send_buffer_size(snd_buf) {
                warn!("Failed to set SO_SNDBUF to {}: {}", snd_buf, e);
            } else {
                debug!("✅ SO_SNDBUF set to {} bytes", snd_buf);
            }
            
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            
            let std_sock: std::net::UdpSocket = socket.into();
            Ok(UdpSocket::from_std(std_sock)?)
        }

        // --- Linux / Unix Optimization Path ---
        #[cfg(unix)]
        {
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))?;
            
            // Set buffer sizes FIRST (before bind)
            let rcv_buf = if opts.so_rcvbuf > 0 { opts.so_rcvbuf } else { BUFFER_SIZE };
            let snd_buf = if opts.so_sndbuf > 0 { opts.so_sndbuf } else { BUFFER_SIZE };

            if let Err(e) = socket.set_recv_buffer_size(rcv_buf) {
                warn!("Failed to set SO_RCVBUF: {}", e);
            } else {
                debug!("✅ SO_RCVBUF set to {} bytes", rcv_buf);
            }
            
            if let Err(e) = socket.set_send_buffer_size(snd_buf) {
                warn!("Failed to set SO_SNDBUF: {}", e);
            } else {
                debug!("✅ SO_SNDBUF set to {} bytes", snd_buf);
            }
            
            // Enable SO_REUSEADDR (Basic)
            if let Err(e) = socket.set_reuse_address(true) {
                warn!("Failed to set SO_REUSEADDR: {}", e);
            }

            // Enable SO_REUSEPORT (Linux/Unix High Performance) if configured
            // This allows multiple threads/processes to bind to the same port
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            {
                if opts.so_reuseport {
                    if let Err(e) = socket.set_reuse_port(true) {
                        warn!("Failed to set SO_REUSEPORT: {}", e);
                    } else {
                        debug!("✅ SO_REUSEPORT enabled");
                    }
                } else {
                    debug!("SO_REUSEPORT disabled by config");
                }
            }

            // Linux deep tuning: busy_poll + priority (best-effort)
            #[cfg(target_os = "linux")]
            {
                let fd = socket.as_raw_fd();
                // SO_BUSY_POLL (microseconds)
                let busy_poll: libc::c_int = 50;
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BUSY_POLL,
                        &busy_poll as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    debug!("SO_BUSY_POLL not applied ({}): {}", busy_poll, std::io::Error::last_os_error());
                }

                // SO_PRIORITY
                let priority: libc::c_int = 6;
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_PRIORITY,
                        &priority as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    debug!("SO_PRIORITY not applied ({}): {}", priority, std::io::Error::last_os_error());
                }
            }

            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            
            let std_sock: std::net::UdpSocket = socket.into();
            Ok(UdpSocket::from_std(std_sock)?)
        }
    }

    /// Set CPU affinity for the current thread
    #[cfg(target_os = "linux")]
    pub fn set_cpu_affinity(core_id: usize) {
        use core_affinity;
        if let Some(core_ids) = core_affinity::get_core_ids() {
            if core_id < core_ids.len() {
                core_affinity::set_for_current(core_ids[core_id]);
                debug!("🧵 Thread bound to CPU Core #{}", core_id);
            }
        }
    }

    pub async fn run_udp(&self, token: tokio_util::sync::CancellationToken) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.socket_opts.batch_io {
                return self.run_udp_linux(token).await;
            } else {
                 return self.run_udp_standard(token).await;
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            self.run_udp_standard(token).await
        }
    }

    /*
    #[cfg(not(target_os = "linux"))]
    */
    async fn run_udp_standard(&self, token: tokio_util::sync::CancellationToken) -> Result<()> {
        info!("👂 UDP Server (Worker Pool) starting on {}", self.addr);

        // Retry logic for binding socket (Critical for Hot Reload on Windows)
        let mut retries = 5;
        let socket = loop {
             match Self::create_udp_socket(&self.addr, &self.socket_opts) {
                Ok(s) => break s,
                Err(e) => {
                    if retries == 0 {
                         return Err(anyhow::anyhow!("Failed to bind {}: {}", self.addr, e));
                    }
                    warn!("Bind failed on {} ({}). Retrying in 300ms... ({} attempts left)", self.addr, e, retries);
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    retries -= 1;
                }
             }
        };

        let socket = Arc::new(socket);
        println!("DEBUG: Socket bound successfully to {}. Loop started.", self.addr);

        // Determine worker count
        let num_workers = if self.socket_opts.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or_else(|_| 4)
        } else {
            self.socket_opts.workers
        };

        // Create task channel (Main Loop -> Workers) - async_channel supports multiple receivers
        let (task_tx, task_rx) = async_channel::bounded::<(Bytes, SocketAddr)>(4096);

        // Spawn Worker Pool
        for worker_id in 0..num_workers {
            let rx = task_rx.clone();
            let socket_clone = socket.clone();
            let hot_reload = self.hot_reload.clone();
            let entry_name = self.entry_name.clone();

            tokio::spawn(async move {
                while let Ok((packet_data, src)) = rx.recv().await {
                    if let Err(e) = Self::handle_packet(
                        socket_clone.clone(),
                        packet_data,
                        src,
                        hot_reload.clone(),
                        entry_name.clone()
                    ).await {
                        debug!("Worker {}: Query processing failed: {}", worker_id, e);
                    }
                }
            });
        }
        info!("🧵 Worker Pool: {} workers spawned", num_workers);

        // [Opt] Use BytesMut for zero-copy receive (reuses buffer memory)
        let mut buf = BytesMut::with_capacity(4096);

        // Main Loop: Receive packets and dispatch to workers
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("🛑 UDP Server on {} stopping...", self.addr);
                    break;
                }
                res = socket.recv_buf_from(&mut buf) => {
                    let (len, src) = match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("UDP recv error: {}", e);
                            continue;
                        }
                    };

                    metrics::inc_query("udp");

                    // Validate DNS packet size
                    const MAX_DNS_PACKET_SIZE: usize = 4096;
                    if len > MAX_DNS_PACKET_SIZE || len < 12 {
                        debug!("Invalid DNS packet size: {} bytes from {}", len, src);
                        buf.clear();
                        continue;
                    }

                    // [Opt] Zero-copy extract: takes ownership of data without copying
                    let packet_data = buf.split_to(len).freeze();

                    // Ensure buffer has capacity for next packet
                    if buf.capacity() < 4096 {
                        buf.reserve(4096 - buf.capacity());
                    }

                    // Dispatch to worker pool (non-blocking send)
                    if let Err(_) = task_tx.try_send((packet_data, src)) {
                        debug!("Worker pool channel full, dropping packet from {}", src);
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn run_udp_linux(&self, token: tokio_util::sync::CancellationToken) -> Result<()> {
        use crate::server::batch_io::BatchIo;
        use crate::server::batch_sender::BatchSender;
        use tokio::sync::mpsc;

        info!("👂 UDP Server (Linux Optimized: recvmmsg + sendmmsg + WorkerPool) starting on {}", self.addr);
        
        // 1. Setup Socket
        let std_socket = Self::create_udp_socket(&self.addr, &self.socket_opts)?.into_std()?;
        let socket_arc = Arc::new(tokio::net::UdpSocket::from_std(std_socket.try_clone()?)?);
        
        // 2. Setup BatchIo (Receiver)
        let mut batch_rx = BatchIo::new(std_socket)?;
        
        // 3. Setup BatchSender (Sender)
        const TX_BATCH_SIZE: usize = 64; 
        let mut batch_tx = BatchSender::new(socket_arc.clone(), TX_BATCH_SIZE);

        // 4. Create Response Channel (Workers -> Main Loop)
        let (resp_tx, mut resp_rx) = mpsc::channel::<(Bytes, SocketAddr)>(4096);

        // 5. Create Task Channel (Main Loop -> Workers)
        // Optimized: We don't need to pass Plugin or EntryName per packet, Workers "know" their context.
        let num_workers = if self.socket_opts.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or_else(|_| 4) // Fallback to 4 if detection fails
        } else {
            self.socket_opts.workers
        };
        let (task_tx, task_rx) = async_channel::bounded::<(Bytes, SocketAddr, mpsc::Sender<(Bytes, SocketAddr)>)>(4096);
        
        // 6. Spawn Worker Pool (reuse tasks instead of spawn per packet)
        for worker_id in 0..num_workers {
            let rx = task_rx.clone();
            // Capture HotReload Context
            let hot_reload = self.hot_reload.clone();
            let entry_name = self.entry_name.clone();

            tokio::spawn(async move {
                while let Ok((packet_data, src, resp_sender)) = rx.recv().await {
                    // Process logic using captured HotReload context
                    match Self::process_request_bytes(packet_data, src, hot_reload.clone(), entry_name.clone()).await {
                        Ok(Some(resp_bytes)) => {
                            if let Err(_) = resp_sender.send((resp_bytes, src)).await {
                                debug!("Worker {}: Response dropped", worker_id);
                            }
                        },
                        Ok(None) => {}, // No response needed
                        Err(e) => debug!("Worker {}: Query failed: {}", worker_id, e),
                    }
                }
            });
        }
        info!("🧵 Worker Pool: {} workers spawned", num_workers);

        // 7. Dynamic Flush Timer (Zero CPU when idle)
        use std::pin::Pin;
        use tokio::time::{sleep_until, Instant, Sleep};
        
        const FLUSH_DELAY: std::time::Duration = std::time::Duration::from_millis(10);
        let mut flush_timer: Option<Pin<Box<Sleep>>> = None;
        let mut last_tune = Instant::now();

        loop {
            tokio::select! {
                // A. Stop Signal
                _ = token.cancelled() => {
                    info!("🛑 UDP Server (Linux) on {} stopping...", self.addr);
                    break;
                }

                // B. Dynamic Flush Timer (only when active)
                _ = async {
                    if let Some(ref mut timer) = flush_timer {
                        timer.as_mut().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    if !batch_tx.is_empty() {
                        if let Err(e) = batch_tx.flush() {
                            warn!("Batch flush failed (timer): {}", e);
                        }
                    }
                    flush_timer = None;
                }

                // C. Receive Responses from Workers
                Some((data, dest)) = resp_rx.recv() => {
                    if batch_tx.push(data, dest) {
                        if let Err(e) = batch_tx.flush() {
                            warn!("Batch flush failed (full): {}", e);
                        }
                        flush_timer = None;
                    } else {
                        if flush_timer.is_none() {
                            flush_timer = Some(Box::pin(sleep_until(Instant::now() + FLUSH_DELAY)));
                        }
                    }
                }

                // D. Receive Packets from Kernel (recvmmsg)
                res = batch_rx.recv_batch() => {
                    let count = match res {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Batch recv error: {}", e);
                            continue;
                        }
                    };

                    if last_tune.elapsed() >= std::time::Duration::from_millis(500) {
                        let qps = crate::autopilot::get_current_qps();
                        batch_rx.auto_tune_batch_size(qps);
                        last_tune = Instant::now();
                    }
            
                    for i in 0..count {
                        if let Some((data, src)) = batch_rx.get_packet(i) {
                            metrics::inc_query("udp");

                            const MAX_DNS_PACKET_SIZE: usize = 4096;
                            let len = data.len();
                            if len > MAX_DNS_PACKET_SIZE || len < 12 { continue; }
                            
                            // Use Bytes for zero-copy (reference counted)
                            let packet_data = Bytes::copy_from_slice(data);
                            let tx_clone = resp_tx.clone();

                            // Send to Worker Pool (no spawn overhead!)
                            if let Err(_) = task_tx.try_send((packet_data, src, tx_clone)) {
                                debug!("Task queue full, dropping packet");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Optimized process_request using Bytes (zero-copy path)
    async fn process_request_bytes(
        data: Bytes,
        src: SocketAddr,
        hot_reload: Arc<HotReloadManager>, // [NEW]
        entry_name: String,               // [NEW]
    ) -> Result<Option<Bytes>> {
        let start_time = std::time::Instant::now();
        
        // [ZERO-COPY] Create Context from raw bytes
        let mut ctx = match Context::from_bytes(data, src) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to parse DNS packet from {}: {}", src, e);
                return Ok(None);
            }
        };
        
        // Precompute common query attributes used by plugins
        ctx.precompute();

        // Extract domain name and type for stats
        let (domain, qtype) = ctx.request.query()
            .map(|q| (q.name().to_string(), q.query_type().to_string()))
            .unwrap_or((String::new(), "UNKNOWN".to_string()));
        let client_ip = src.ip().to_string();
        
        // [HOT RELOAD] Resolve entry point dynamically
        if let Some(entry) = hot_reload.get_entry(&entry_name) {
            // Execute Plugin Chain (entry point handles the sequence)
            if let Err(e) = entry.handle(&mut ctx).await {
                warn!("Plugin chain execution error: {}", e);
                return Ok(None);
            }
        } else {
             // Avoid spamming logs if entry is transiently missing during reload
             debug!("⚠️ Entry point '{}' not found during hot reload", entry_name);
             return Ok(None);
        }
        
        // Execute Post-Process Hooks (e.g. Cache Write)
        if ctx.has_response() {
            let hooks = ctx.post_process_hooks.clone();
            for hook in hooks {
                if let Err(e) = hook.on_response(&mut ctx).await {
                    warn!("Post-process hook failed: {}", e);
                }
            }
        }
        
        // Record stats
        let latency_us = start_time.elapsed().as_micros() as u64;
        STATS.record_query(&domain, &client_ip, latency_us);

        // Record extended stats (RCODE) - checks both response and raw_response
        let rcode_str = ctx.get_rcode_as_string();
        STATS.record_details(&qtype, &rcode_str);

        // Log to Query Log
        let rcode_str = ctx.get_rcode_as_string();
        crate::query_log::log_request(
            client_ip.clone(), 
            domain.clone(), 
            qtype.clone(), 
            "Default".to_string(),
            None,
            latency_us / 1000, 
            rcode_str
        ).await;
        
        // [ZERO-COPY] Use unified response_bytes() method
        Ok(ctx.response_bytes())
    }



    async fn handle_packet(
        socket: Arc<UdpSocket>,
        data: Bytes,
        src: SocketAddr,
        hot_reload: Arc<HotReloadManager>,
        entry_name: String,
    ) -> Result<()> {
        if let Some(resp_bytes) = Self::process_request(data, src, hot_reload, entry_name).await? {
            socket.send_to(&resp_bytes, &src).await?;
        }
        Ok(())
    }

    async fn process_request(
        data: Bytes,
        src: SocketAddr,
        hot_reload: Arc<HotReloadManager>, // [NEW]
        entry_name: String,               // [NEW]
    ) -> Result<Option<Bytes>> {
        let start_time = std::time::Instant::now();
        
        // [ZERO-COPY] Create Context from raw bytes
        let mut ctx = match Context::from_bytes(data, src) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to parse DNS packet from {}: {}", src, e);
                return Ok(None);
            }
        };

        // Precompute common query attributes used by plugins
        ctx.precompute();

        // Extract domain name and type for stats
        let (domain, qtype) = ctx.request.query()
            .map(|q| (q.name().to_string(), q.query_type().to_string()))
            .unwrap_or((String::new(), "UNKNOWN".to_string()));
        let client_ip = src.ip().to_string();

        // [HOT RELOAD] Resolve entry point dynamically
        if let Some(entry) = hot_reload.get_entry(&entry_name) {
            // Execute Plugin Chain
            if let Err(e) = entry.handle(&mut ctx).await {
                warn!("Plugin chain execution error: {}", e);
                return Ok(None);
            }
        } else {
             debug!("⚠️ Entry point '{}' not found during hot reload", entry_name);
             return Ok(None);
        }

        // Execute Post-Process Hooks (e.g. Cache Write)
        if ctx.has_response() {
            let hooks = ctx.post_process_hooks.clone();
            for hook in hooks {
                if let Err(e) = hook.on_response(&mut ctx).await {
                    warn!("Post-process hook failed: {}", e);
                }
            }
        }

        // Record stats
        let latency_us = start_time.elapsed().as_micros() as u64;
        STATS.record_query(&domain, &client_ip, latency_us);

        // Record extended stats (RCODE) - checks both response and raw_response
        let rcode_str = ctx.get_rcode_as_string();
        STATS.record_details(&qtype, &rcode_str);

        // Log to Query Log
        let rcode_str = ctx.get_rcode_as_string();
        crate::query_log::log_request(
            client_ip.clone(), 
            domain.clone(), 
            qtype.clone(), 
            "Default".to_string(), 
            None, 
            latency_us / 1000, 
            rcode_str
        ).await;

        // [ZERO-COPY] Use unified response_bytes() method
        if let Some(resp_bytes) = ctx.response_bytes() {
            debug!("✅ Prepared response for {} ({} bytes)", src, resp_bytes.len());
            Ok(Some(resp_bytes))
        } else {
            Ok(None)
        }
    }



    pub async fn run_tcp(&self) -> Result<()> {
        use tokio::net::TcpListener;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        info!("👂 TCP Server starting on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (mut socket, src) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    continue;
                }
            };
            
            let hot_reload = self.hot_reload.clone();
            let entry_name = self.entry_name.clone();
            
            tokio::spawn(async move {
                // [CpuAffinity] Bind worker thread to core
                // ... (omitted)

                // Read 2-byte length
                let mut len_buf = [0u8; 2];
                if let Err(_) = socket.read_exact(&mut len_buf).await {
                     return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                
                // Validate size
                if len > 65535 { return; } 

                // Read body
                let mut buf = vec![0u8; len];
                if let Err(e) = socket.read_exact(&mut buf).await {
                    debug!("Failed to read TCP body: {}", e);
                    return;
                }
                
                // Process
                match Self::process_request(Bytes::from(buf), src, hot_reload, entry_name).await {
                    Ok(Some(resp_bytes)) => {
                        let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                        if socket.write_all(&resp_len).await.is_err() { return; }
                        if socket.write_all(resp_bytes.as_ref()).await.is_err() { return; }
                    },
                    Ok(None) => {}, // No response
                    Err(e) => debug!("TCP request processing error: {}", e),
                }
            });
        }
    }

    pub async fn run_dot(&self) -> Result<()> {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tls_conf = self.tls_config.as_ref().ok_or_else(|| anyhow::anyhow!("TLS config missing for DoT"))?;
        let server_config = crate::server::tls_loader::build_dot_config(&tls_conf.cert, &tls_conf.key)?;
        let acceptor = TlsAcceptor::from(server_config);

        info!("👂 DoT Server (DNS over TLS) starting on {}", self.addr);
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, src) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("DoT accept error: {}", e);
                    continue;
                }
            };
            
            let acceptor = acceptor.clone();
            let hot_reload = self.hot_reload.clone();
            let entry_name = self.entry_name.clone();

            tokio::spawn(async move {
                // 1. TLS Handshake
                let mut stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("DoT TLS handshake failed from {}: {}", src, e);
                        return;
                    }
                };

                // 2. Read DNS Message (RFC 7858: 2-byte length prefix)
                loop {
                    let mut len_buf = [0u8; 2];
                    // Read length with timeout (5s)
                    if let Err(_) = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut len_buf)).await {
                        return; // Timeout or Error
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    
                    if len > 65535 { return; }

                    let mut buf = vec![0u8; len];
                    if let Err(_) = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut buf)).await {
                         debug!("DoT read body timeout");
                         return;
                    }

                    // 3. Process
                    match Self::process_request(Bytes::from(buf), src, hot_reload.clone(), entry_name.clone()).await {
                        Ok(Some(resp_bytes)) => {
                            let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                            if stream.write_all(&resp_len).await.is_err() { return; }
                            if stream.write_all(resp_bytes.as_ref()).await.is_err() { return; }
                        },
                        Ok(None) => {}, 
                        Err(e) => debug!("DoT processing error: {}", e),
                    }
                    // RFC 7858 says persistent connections are encouraged.
                    // So we loop back to read next query.
                }
            });
        }
    }

    pub async fn run_doq(&self) -> Result<()> {
        let tls_conf = self.tls_config.as_ref().ok_or_else(|| anyhow::anyhow!("TLS config missing for DoQ"))?;
        let crypto_config = crate::server::tls_loader::build_doq_config(&tls_conf.cert, &tls_conf.key)?;
        
        let quic_backend = quinn::crypto::rustls::QuicServerConfig::try_from(crypto_config)?;
        let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_backend));
        
        // Optimized Transport Config
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(std::time::Duration::from_millis(5000)));
        server_config.transport_config(std::sync::Arc::new(transport));

        let endpoint = quinn::Endpoint::server(server_config, self.addr.parse()?)?;
        
        info!("👂 DoQ Server (DNS over QUIC) starting on {}", self.addr);
        
        while let Some(conn) = endpoint.accept().await {
             let hot_reload = self.hot_reload.clone();
             let entry_name = self.entry_name.clone();
             
             tokio::spawn(async move {
                 let connection = match conn.await {
                     Ok(c) => c,
                     Err(e) => {
                         debug!("DoQ Handshake failed: {}", e);
                         return;
                     }
                 };
                 let src = connection.remote_address();
                 
                 // Handle Bidirectional Streams (RFC 9250)
                 while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                     let hot_reload = hot_reload.clone();
                     let entry_name = entry_name.clone();
                     tokio::spawn(async move {
                         // Read Message (2-byte Length-prefixed)
                         let mut len_buf = [0u8; 2];
                         if recv.read_exact(&mut len_buf).await.is_err() { return; }
                         let len = u16::from_be_bytes(len_buf) as usize;
                         
                         // Safety Limit
                         if len > 65535 { return; }

                         let mut buf = vec![0u8; len];
                         if recv.read_exact(&mut buf).await.is_err() { return; }
                         
                         // Process
                         match Self::process_request(Bytes::from(buf), src, hot_reload, entry_name).await {
                             Ok(Some(resp_bytes)) => {
                                 let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                                 // Write Length + Body
                                 if send.write_all(&resp_len).await.is_ok() {
                                     let _ = send.write_all(resp_bytes.as_ref()).await;
                                 }
                                 // Finish stream (DoQ uses one stream per query-response usually)
                                 let _ = send.finish(); 
                             },
                             _ => {}
                         }
                     });
                 }
             });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct DohState {
    hot_reload: Arc<HotReloadManager>,
    entry_name: String,
}

async fn handle_doh_bytes(
    state: &DohState,
    client_addr: SocketAddr,
    data: Bytes,
) -> Result<Bytes> {
    let resp = DnsServer::process_request(
        data,
        client_addr,
        state.hot_reload.clone(),
        state.entry_name.clone(),
    ).await?;

    resp.ok_or_else(|| anyhow::anyhow!("No response generated"))
}

async fn doh_get(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<DohState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let dns_param = match params.get("dns") {
        Some(v) => v,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let decoded = match URL_SAFE_NO_PAD.decode(dns_param.as_bytes()) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if decoded.is_empty() || decoded.len() > 65535 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match handle_doh_bytes(&state, addr, Bytes::from(decoded)).await {
        Ok(resp_bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/dns-message"));
            headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
            (StatusCode::OK, headers, resp_bytes).into_response()
        }
        Err(e) => {
            debug!("DoH GET failed from {}: {}", addr, e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn doh_post(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<DohState>,
    headers: HeaderMap,
    body: AxumBytes,
) -> impl IntoResponse {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with("application/dns-message") {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    if body.is_empty() || body.len() > 65535 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match handle_doh_bytes(&state, addr, Bytes::from(body)).await {
        Ok(resp_bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/dns-message"));
            headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
            (StatusCode::OK, headers, resp_bytes).into_response()
        }
        Err(e) => {
            debug!("DoH POST failed from {}: {}", addr, e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

impl DnsServer {
    /// DoH (DNS over HTTPS) Server
    /// RFC 8484: DNS Queries over HTTPS (DoH)
    pub async fn run_doh(&self) -> Result<()> {
        info!("👂 DoH Server (DNS over HTTPS) starting on {}", self.addr);

        let state = DohState {
            hot_reload: self.hot_reload.clone(),
            entry_name: self.entry_name.clone(),
        };

        let app = Router::new()
            .route("/dns-query", get(doh_get).post(doh_post))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;

        if let Some(tls_conf) = &self.tls_config {
            let tls = crate::server::tls_loader::build_doh_config(&tls_conf.cert, &tls_conf.key)?;
            let acceptor = TlsAcceptor::from(tls);

            loop {
                let (stream, peer_addr) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("DoH TLS handshake failed from {}: {}", peer_addr, e);
                            return;
                        }
                    };

                    let svc = app.clone().layer(Extension(ConnectInfo(peer_addr)));
                    let svc = svc.map_request(|req: axum::http::Request<Incoming>| req.map(AxumBody::new));
                    let hyper_svc = TowerToHyperService::new(svc);
                    let io = TokioIo::new(tls_stream);

                    if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, hyper_svc)
                        .await
                    {
                        debug!("DoH connection error from {}: {}", peer_addr, e);
                    }
                });
            }
        } else {
            warn!("⚠️ DoH is running over HTTP (no TLS). Consider configuring TLS.");
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
        }

        Ok(())
    }
}
