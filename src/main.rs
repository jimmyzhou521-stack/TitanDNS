#![allow(dead_code)]
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::collections::HashMap;
#[cfg(all(feature = "jemalloc", any(target_os = "linux", target_os = "macos")))]
use std::env;
 
use tracing::{info, error, debug, warn, Level};
use anyhow::Result;
use sha2::{Digest, Sha256};

#[cfg(all(feature = "jemalloc", any(target_os = "linux", target_os = "macos")))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", any(target_os = "linux", target_os = "macos")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Declare Modules
mod config;
mod core;
mod plugins;
mod server;
mod singbox;
mod api;
mod config_watcher;
mod bpf;
mod plugin_factory;
mod health;  // 健康检查模块
mod socks5_udp;  // SOCKS5 UDP 代理支持
mod stats;  // 统计收集模块
mod query_log; // 查询日志模块
mod autopilot; // AIOps 智能运维模块

// use axum::{routing::get, Router}; // 未使用
// use std::net::SocketAddr;

use crate::core::plugin::Plugin;
use crate::server::DnsServer;




/// TitanDNS: Next-Gen DNS Forwarder
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn compute_file_hash(path: &str) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&hash[..8]);
    Some(u64::from_le_bytes(first8))
}

#[cfg(all(feature = "jemalloc", any(target_os = "linux", target_os = "macos")))]
fn log_jemalloc_hint() {
    if env::var("MALLOC_CONF").is_err() {
        info!("jemalloc enabled. Tip: set MALLOC_CONF=\"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,lg_dirty_mult:8\" for lower latency/fragmentation");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Rustls 0.23: Explicitly install standard crypto provider to avoid panic
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    // 1. Load Config first (before logging)
    let config = match crate::config::Config::load_from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Initialize Logging
    // Assuming `init_tracing` is a new function that replaces the old logging init.
    // This part of the diff is a bit ambiguous, but I'll follow the provided "Code Edit" structure.
    // If `init_tracing` is not defined, this will cause a compilation error.
    // For now, I'll keep the original logging init and just add the query_log part.
    // Re-reading the instruction: "Add mod query_log and init_query_log call".
    // The provided "Code Edit" block shows a *replacement* of the logging init.
    // I will assume `init_tracing` is meant to be used and the old `init_logging` functions are removed.
    // However, since `init_tracing` is not defined in the provided context, I will
    // stick to the original logging initialization and only add the `query_log` part.
    // This is to ensure the resulting code is syntactically correct and compiles,
    // as `init_tracing` is not part of the original document.

    // Original logging initialization:
    if args.verbose {
        // Assuming init_logging(true) is still valid or replaced elsewhere
        // For now, I'll keep the original structure as the instruction is about `query_log`.
        // If `init_tracing` was meant to be added, it would need to be defined.
        // Given the strict instruction to "make the change faithfully and without making any unrelated edits",
        // I will not introduce `init_tracing` or remove `init_logging` functions.
        // I will only add the `query_log` module and its initialization call.
        init_logging(true); // This function is not defined in the provided context, but was in the original code.
    } else {
        // This function is not defined in the provided context, but was in the original code.
        init_logging_from_config(&config.log.level, config.log.file.as_ref());
    }

    #[cfg(all(feature = "jemalloc", any(target_os = "linux", target_os = "macos")))]
    log_jemalloc_hint();

    // 3. Initialize Global Components
    // Query Log
    // Query Log
    query_log::init_query_log(config.query_log.enabled, config.query_log.max_size);
    crate::stats::STATS.set_blocked_limit(config.query_log.recent_blocked_limit);
    info!("📜 Query Log: enabled={}, max_size={}, recent_blocked_limit={}", 
          config.query_log.enabled, config.query_log.max_size, config.query_log.recent_blocked_limit);

    info!("🚀 TitanDNS v6.7.0 (Slim Core) is starting...");
    debug!("📂 Loaded config from {:?}", args.config);

    let config_path_str = args.config.to_string_lossy().to_string();
    let mut last_config_hash = compute_file_hash(&config_path_str).unwrap_or(0);

    // Setup Config Watcher
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel(1);
    let config_path = config_path_str.clone();
    let watcher = crate::config_watcher::ConfigWatcher::new(config_path.clone());
    
    // Watch in background
    tokio::spawn(async move {
        if let Err(e) = watcher.watch(move || {
            let _ = reload_tx.blocking_send(());
            Ok(())
        }).await {
            error!("Config watcher failed: {}", e);
        }
    });

    // 4. Initialize Global State (Survives Reloads)
    let proxy_state = Arc::new(AtomicBool::new(false));
    let mut discovered_socks_port = None;
    let mut system_handles = Vec::new();

    // 4.1 Sing-box Auto-Discovery
    if config.singbox.auto_discover {
        let mut sb_monitor = singbox::SingBoxMonitor::new(Some(proxy_state.clone()));
        sb_monitor.auto_discover();
        discovered_socks_port = Some(sb_monitor.socks_port);
        system_handles.push(tokio::spawn(async move { sb_monitor.run_monitor_loop().await; }));
    } else {
        proxy_state.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    
    // 4.2 Initialize eBPF Filter (Linux Only)
    #[cfg(target_os = "linux")]
    let ebpf_handle = if let Some(ebpf_conf) = &config.ebpf {
        let interface = ebpf_conf.interface.clone();
        let path = ebpf_conf.bpf_path.clone().unwrap_or_else(|| "titan_dns_filter.o".to_string());
        let blacklist = ebpf_conf.blacklist.clone();
        
        let mut filter = crate::bpf::DnsBpfFilter::new(interface.clone());
        match filter.load_and_attach(std::path::Path::new(&path)) {
            Ok(_) => {
                info!("✅ eBPF Filter active on {}", interface);
                if let Err(e) = filter.populate_blacklist(&blacklist) {
                    error!("❌ Failed to populate blacklist: {}", e);
                }
                let filter_arc = Arc::new(tokio::sync::Mutex::new(filter));
                let _filter_ref = filter_arc.clone();
                system_handles.push(tokio::spawn(async move {
                     std::future::pending::<()>().await;
                }));
                Some(filter_arc)
            },
            Err(e) => {
                error!("❌ Failed to attach eBPF filter: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 4.3 Init Shared Plugins
    #[cfg(target_os = "linux")]
    let shared_plugins = crate::plugin_factory::create_shared_plugins(&config, ebpf_handle);

    #[cfg(not(target_os = "linux"))]
    let shared_plugins = crate::plugin_factory::create_shared_plugins(&config);

    let shared_plugins_ref = Arc::new(shared_plugins); 
    
    // 5. Setup Reload Channel
    let (updates_tx, _) = tokio::sync::broadcast::channel::<Arc<crate::config::Config>>(16);

    // Initial Start
    let updates_tx_clone = updates_tx.clone();
    let instance = start_instance(
        &config, 
        std::path::PathBuf::from(&args.config),
        proxy_state.clone(), 
        discovered_socks_port, 
        shared_plugins_ref.clone(), 
        updates_tx_clone
    ).await;
    
    if instance.handles.is_empty() {
            error!("⚠️ No services started. Waiting for config change...");
    }

    loop {
        tokio::select! {
            // ... (SIGINT/SIGTERM unchanged) ...
            _ = tokio::signal::ctrl_c() => {
                info!("👋 Shutting down (SIGINT)...");
                instance.shutdown_token.cancel();
                for h in &instance.handles { h.abort(); }
                // Also kill system handles
                for h in &system_handles { h.abort(); }
                break;
            }
            // Handle SIGTERM (Systemd / Kill) - Linux/macOS Only
            _ = async {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    match signal(SignalKind::terminate()) {
                        Ok(mut sigterm) => { sigterm.recv().await; },
                        Err(e) => {
                            error!("Failed to register SIGTERM handler: {}", e);
                            std::future::pending::<()>().await
                        }
                    }
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await
            } => {
                info!("👋 Shutting down (SIGTERM)...");
                instance.shutdown_token.cancel();
                for h in &instance.handles { h.abort(); }
                for h in &system_handles { h.abort(); }
                break;
            }
            // Handle Config Reload
            _ = reload_rx.recv() => {
                info!("🔄 Config file changed.");
                let new_hash = compute_file_hash(&config_path);
                if let Some(h) = new_hash {
                    if h == last_config_hash {
                        info!("✅ Config unchanged (hash match), skip reload");
                        continue;
                    }
                }
                match crate::config::Config::load_from_file(&args.config) {
                    Ok(new_config) => {
                        let ac_nc = Arc::new(new_config.clone());
                        
                        // 1. Send Update to UDP Workers
                        if let Err(e) = updates_tx.send(ac_nc.clone()) {
                            warn!("Failed to broadcast config update: {}", e);
                        }
                        
                        // 2. Update Main Runtime (TCP/API) Manager
                        // We rebuild the plugin chain using the existing shared plugins and proxy state
                        let registry_data = crate::plugin_factory::create_runtime_registry(
                            &new_config, 
                            proxy_state.clone(), 
                            discovered_socks_port,
                            &shared_plugins_ref 
                        ).await;
                        
                        instance.hot_reload_manager.update(registry_data.entry_points, 1);
                        if let Some(h) = new_hash {
                            last_config_hash = h;
                        } else if let Some(h) = compute_file_hash(&config_path) {
                            last_config_hash = h;
                        }
                        
                        // config = new_config; // Removed unused assignment
                        info!("✅ Hot Reload applied successfully!");
                    },
                    Err(e) => error!("❌ Failed to load new config: {}", e),
                }
            }
        }
    }



    info!("👋 TitanDNS stopped. Bye!");
    Ok(())
}

struct Instance {
    handles: Vec<tokio::task::JoinHandle<()>>,
    shutdown_token: tokio_util::sync::CancellationToken,
    plugin_registry: HashMap<String, crate::plugins::AnyPlugin>,
    hot_reload_manager: Arc<crate::core::hot_reload::HotReloadManager>,
}

async fn start_instance(
    config: &crate::config::Config,
    config_path: std::path::PathBuf,
    proxy_state: Arc<AtomicBool>,
    discovered_socks_port: Option<u16>,
    shared_plugins_ref: Arc<crate::plugin_factory::SharedPlugins>,
    updates_tx: tokio::sync::broadcast::Sender<Arc<crate::config::Config>>
) -> Instance {
    let mut handles = Vec::new();
    let shutdown_token = tokio_util::sync::CancellationToken::new();

    // Phase 2: Create Main Runtime Registry (for TCP/API)
    let registry_data = crate::plugin_factory::create_runtime_registry(
        config, 
        proxy_state.clone(), 
        discovered_socks_port,
        &shared_plugins_ref
    ).await;
    
    let plugin_registry = registry_data.plugins;
    let server_entry_points = registry_data.entry_points;
    let api_cache_handle = registry_data.api_cache_handle;

    // [HOT RELOAD] Initialize the Manager with current entry points
    let hot_reload_manager = Arc::new(crate::core::hot_reload::HotReloadManager::new(server_entry_points.clone()));

    // [AIOps] Prefetch hot domains / predictive prefetch (cold start)
    let prefetch_plugin = if let Some(p) = plugin_registry.get("upstream_local").cloned() {
        info!("🔥 AIOps prefetch using upstream_local");
        Some(p)
    } else if let Some(entry_name) = config.servers.first().map(|s| s.entry.clone()) {
        if let Some(p) = server_entry_points.get(&entry_name).cloned() {
            info!("🔥 AIOps prefetch fallback to entry={}", entry_name);
            Some(p)
        } else {
            warn!("⚠️ AIOps prefetch disabled: entry '{}' not found", entry_name);
            None
        }
    } else {
        warn!("⚠️ AIOps prefetch disabled: no server entry configured");
        None
    };

    if let Some(prefetch_entry) = prefetch_plugin {
        let prefetch_aaaa = std::env::var("TITANDNS_PREFETCH_AAAA")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "no" || v == "off")
            })
            .unwrap_or(true);

        let prefetch_entry = prefetch_entry.clone();
        let prefetcher = std::sync::Arc::new(move |domain: String| {
            if domain.is_empty() {
                return;
            }

            let entry = prefetch_entry.clone();
            tokio::spawn(async move {
                use hickory_proto::op::{Message, MessageType, OpCode, Query};
                use hickory_proto::rr::{Name, RecordType};

                let client_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

                if prefetch_aaaa {
                    for record_type in [RecordType::A, RecordType::AAAA] {
                        let name = match Name::from_ascii(&domain) {
                            Ok(n) => n,
                            Err(_) => return,
                        };

                        let mut msg = Message::new();
                        msg.set_id(0xBEEF);
                        msg.set_message_type(MessageType::Query);
                        msg.set_op_code(OpCode::Query);
                        msg.set_recursion_desired(true);
                        msg.add_query(Query::query(name, record_type));

                        let mut ctx = crate::core::context::Context::new(msg, client_addr);
                        let _ = entry.handle(&mut ctx).await;
                    }
                } else {
                    let name = match Name::from_ascii(&domain) {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let mut msg = Message::new();
                    msg.set_id(0xBEEF);
                    msg.set_message_type(MessageType::Query);
                    msg.set_op_code(OpCode::Query);
                    msg.set_recursion_desired(true);
                    msg.add_query(Query::query(name, RecordType::A));

                    let mut ctx = crate::core::context::Context::new(msg, client_addr);
                    let _ = entry.handle(&mut ctx).await;
                }
            });
        });

        crate::autopilot::HOT_DOMAINS.set_prefetch_callback({
            let prefetcher = prefetcher.clone();
            move |domain| {
                (*prefetcher)(domain);
            }
        });

        crate::autopilot::start_predictive_prefetch_task({
            let prefetcher = prefetcher.clone();
            move |domain| {
                (*prefetcher)(domain);
            }
        });

        crate::autopilot::start_hot_domain_prefetch_task({
            let prefetcher = prefetcher.clone();
            move |domain| {
                (*prefetcher)(domain.to_string());
            }
        });
    }

    // [AIOps] Start AutoPilot background health monitoring
    let shutdown_clone = shutdown_token.clone();
    crate::autopilot::start_autopilot(shutdown_clone);

    // 3. Start Management API & Dashboard
    if let Some(api_conf) = &config.api {
        // ... (unchanged) ...
        let local_www = std::path::PathBuf::from("www");
        let sys_www = std::path::PathBuf::from("/etc/titandns/www");
        
        let www_dir = if local_www.exists() {
            Some(local_www)
        } else if sys_www.exists() {
            Some(sys_www)
        } else {
            None
        };
        
        if let Some(dir) = &www_dir {
            info!("📂 Dashboard serving from: {:?}", dir);
        } else {
            warn!("⚠️ Dashboard static files not found (checked ./www and /etc/titandns/www)");
        }
        
        // ... (api execution) ...
        let state = crate::api::AppState {
            cache: api_cache_handle.clone(),
            stats: None,  // We use global STATS now
            www_dir,
            config_file: config_path.clone(),
        };
        let http_addr = api_conf.http.clone();
        handles.push(tokio::spawn(async move {
            crate::api::start_api_server(http_addr, state).await;
        }));
    }
    
    // 4. Start UDP Servers
    for srv_conf in &config.servers {
        if server_entry_points.contains_key(&srv_conf.entry) {
            let addr = srv_conf.addr.clone();
            let proto = srv_conf.protocol.clone();
            let entry_name = srv_conf.entry.clone();
            
            info!("👂 Starting Server on {} (entry: {})", addr, entry_name);
            
            match proto {
                crate::config::Protocol::Udp => {
                    // Multi-Worker with CPU Affinity Support
                    let num_workers = if srv_conf.socket_opts.workers == 0 {
                        num_cpus::get()
                    } else {
                        srv_conf.socket_opts.workers
                    };
                    
                    info!("🚀 Spawning {} UDP workers on {} (Dedicated Threads + Affinity)", num_workers, addr);
                    
                    for worker_id in 0..num_workers {
                        let addr = addr.clone();
                        // Clone config needed for factory
                        let config_clone = config.clone(); 
                        let proxy_state_clone = proxy_state.clone();
                        let socks_port_clone = discovered_socks_port;
                        let entry_name_clone = entry_name.clone();
                        let socket_opts = srv_conf.socket_opts.clone();
                        let token = shutdown_token.clone();
                        // Share the existing shared plugins with the worker
                        // Share the existing shared plugins with the worker
                        let shared_plugins_ref = shared_plugins_ref.clone();
                        // Get Reload Receiver
                        let mut rx = updates_tx.subscribe();
                        
                        // Spawn a dedicated OS thread for this worker
                        std::thread::Builder::new()
                            .name(format!("udp-worker-{}", worker_id))
                            .spawn(move || {
                                // 1. Bind this new thread to a specific CPU core
                                crate::server::affinity::bind_thread_to_cpu(worker_id);
                                
                                // 2. Create a Single-Threaded Tokio Runtime (Multi-Thread flavor for better I/O driver)
                                let rt = tokio::runtime::Builder::new_multi_thread()
                                    .worker_threads(1)
                                    .enable_all()
                                    .build()
                                    .expect("Failed to create worker runtime");
                                
                                // 3. Run the Server Loop inside this Local Runtime
                                rt.block_on(async {
                                    info!("✅ UDP Worker {} initialized on Core {}", worker_id, worker_id);
                                    
                                    // [CRITICAL] Re-create Plugin Chain INSIDE this thread/runtime.
                                    let local_registry = crate::plugin_factory::create_runtime_registry(
                                        &config_clone, 
                                        proxy_state_clone.clone(), 
                                        socks_port_clone,
                                        &shared_plugins_ref
                                    ).await;
                                    
                                    // [HOT RELOAD] Create local manager for this worker
                                    let local_hot_reload = Arc::new(crate::core::hot_reload::HotReloadManager::new(local_registry.entry_points));

                                    if local_hot_reload.get_entry(&entry_name_clone).is_some() {
                                        let server = DnsServer::new(addr.clone(), local_hot_reload.clone(), entry_name_clone.clone(), socket_opts, None);
                                        let token_clone = token.clone();
                                        
                                        // Spawn Server in Background
                                        let mut server_task = tokio::spawn(async move {
                                            if let Err(e) = server.run_udp(token_clone).await {
                                                error!("❌ UDP Worker {} on {} crashed: {}", worker_id, addr, e);
                                            }
                                        });

                                        // Hot Reload Loop
                                        loop {
                                            tokio::select! {
                                                _ = &mut server_task => {
                                                    // Server task finished (crashed or stopped)
                                                    break;
                                                },
                                                res = rx.recv() => {
                                                    match res {
                                                        Ok(new_config) => {
                                                             debug!("🔄 UDP Worker {} reloading config...", worker_id);
                                                             let new_registry_data = crate::plugin_factory::create_runtime_registry(
                                                                 &new_config,
                                                                 proxy_state_clone.clone(),
                                                                 socks_port_clone,
                                                                 &shared_plugins_ref 
                                                             ).await;
                                                             // Atomic Update
                                                             local_hot_reload.update(new_registry_data.entry_points, 1);
                                                        },
                                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        error!("❌ UDP Worker {} failed to find entry point '{}'", worker_id, entry_name_clone);
                                    }
                                });
                            })
                            .expect("Failed to spawn worker thread");
                    }
                },
                crate::config::Protocol::Tcp => {
                    let addr = addr.clone();
                    // We check existence via the main registry, but pass the name to Server
                    if server_entry_points.contains_key(&srv_conf.entry) {
                        let entry_name = srv_conf.entry.clone();
                        let socket_opts = srv_conf.socket_opts.clone();
                        let hot_reload_clone = hot_reload_manager.clone();
                        
                        handles.push(tokio::spawn(async move {
                            let server = DnsServer::new(addr.clone(), hot_reload_clone, entry_name, socket_opts, None);
                            if let Err(e) = server.run_tcp().await {
                                error!("TCP Server {} crashed: {}", addr, e);
                            }
                        }));
                    }
                },
                crate::config::Protocol::Dot => {
                    let addr = addr.clone();
                    if server_entry_points.contains_key(&srv_conf.entry) {
                        let entry_name = srv_conf.entry.clone();
                        let socket_opts = srv_conf.socket_opts.clone();
                        let tls_config = srv_conf.tls.clone();
                        let hot_reload_clone = hot_reload_manager.clone();
                        handles.push(tokio::spawn(async move {
                            let server = DnsServer::new(addr.clone(), hot_reload_clone, entry_name, socket_opts, tls_config);
                            if let Err(e) = server.run_dot().await {
                                error!("DoT Server {} crashed: {}", addr, e);
                            }
                        }));
                    }
                },
                crate::config::Protocol::Doq => {
                    let addr = addr.clone();
                    if server_entry_points.contains_key(&srv_conf.entry) {
                        let entry_name = srv_conf.entry.clone();
                        let socket_opts = srv_conf.socket_opts.clone();
                        let tls_config = srv_conf.tls.clone();
                        let hot_reload_clone = hot_reload_manager.clone();
                        handles.push(tokio::spawn(async move {
                            let server = DnsServer::new(addr.clone(), hot_reload_clone, entry_name, socket_opts, tls_config);
                            if let Err(e) = server.run_doq().await {
                                error!("DoQ Server {} crashed: {}", addr, e);
                            }
                        }));
                    }
                },
                crate::config::Protocol::Doh => {
                    let addr = addr.clone();
                    if server_entry_points.contains_key(&srv_conf.entry) {
                        let entry_name = srv_conf.entry.clone();
                        let socket_opts = srv_conf.socket_opts.clone();
                        let tls_config = srv_conf.tls.clone();
                        let hot_reload_clone = hot_reload_manager.clone();
                        handles.push(tokio::spawn(async move {
                            let server = DnsServer::new(addr.clone(), hot_reload_clone, entry_name, socket_opts, tls_config);
                            if let Err(e) = server.run_doh().await {
                                error!("DoH Server {} crashed: {}", addr, e);
                            }
                        }));
                    }
                },
            }
        } else {
             error!("❌ Server entry point '{}' not found in sequences", srv_conf.entry);
        }
    }

    // 6. Start Metrics Server (Prometheus)
    let metrics_addr: std::net::SocketAddr = "0.0.0.0:9898".parse().expect("Failed to parse metrics address");
    let metrics_router = axum::Router::new()
        .route("/metrics", axum::routing::get(crate::core::metrics::metrics_handler));
    
    handles.push(tokio::spawn(async move {
         info!("📊 Metrics server listening on http://{}", metrics_addr);
         if let Ok(listener) = tokio::net::TcpListener::bind(metrics_addr).await {
             if let Err(e) = axum::serve(listener, metrics_router).await {
                 error!("❌ Metrics server error: {}", e);
             }
         } else {
             error!("❌ Failed to bind Metrics port {}", metrics_addr);
         }
    }));

    Instance {
        handles,
        shutdown_token,
        plugin_registry,
        hot_reload_manager,
    }
}

fn init_logging(verbose: bool) {
    let log_level = if verbose { Level::DEBUG } else { Level::INFO };
    setup_logging(log_level, None);
}

fn init_logging_from_config(level_str: &str, log_path: Option<&String>) {
    let log_level = match level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => {
            eprintln!("⚠️  Invalid log level '{}', defaulting to INFO", level_str);
            Level::INFO
        }
    };
    
    // Extract directory from full path if provided
    let log_dir = log_path.map(|p| {
        std::path::Path::new(p)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_str()
            .unwrap_or(".")
    });

    setup_logging(log_level, log_dir);
}

fn setup_logging(level: Level, log_dir: Option<&str>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    
    // Console output layer
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(true);
    
    // Build subscriber
    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    
    if let Some(dir) = log_dir {
        // File output with daily rotation
        let file_appender = tracing_appender::rolling::daily(dir, "titandns.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        
        // Keep guard alive (leak it for program lifetime)
        std::mem::forget(_guard);
        
        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_ansi(false)
            .with_writer(non_blocking);
        
        tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .with(file_layer)
            .init();
            
        info!("📝 Log rotation enabled: {}/titandns.log (daily)", dir);
    } else {
        // Console only
        tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .init();
    }
}

/// Setup logging with file rotation (called from config)
pub fn setup_logging_with_file(level: Level, log_file: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(true);
    
    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    
    // Parse log file path to get directory
    let path = std::path::Path::new(log_file);
    let dir = path.parent().unwrap_or(std::path::Path::new("/var/log"));
    let filename = path.file_name().unwrap_or(std::ffi::OsStr::new("titandns.log"));
    
    // Daily rotation
    let file_appender = tracing_appender::rolling::daily(dir, filename);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    std::mem::forget(_guard);
    
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(non_blocking);
    
    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();
    
    info!("📝 Log rotation enabled: {} (daily)", log_file);
}

