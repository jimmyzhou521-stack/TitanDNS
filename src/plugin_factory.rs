use crate::config::{Config, PluginType};
use crate::plugins::AnyPlugin;
use crate::plugins::sequence::{Sequence, Step};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing::{info, error, debug};

pub struct PluginRegistry {
    pub plugins: HashMap<String, AnyPlugin>,
    pub entry_points: HashMap<String, AnyPlugin>,
    pub api_cache_handle: Option<Arc<crate::plugins::cache::CachePlugin>>,
}

pub type SharedPlugins = HashMap<String, AnyPlugin>;

/// Phase 1: Create plugins that are shared across all threads (Cache, GeoIP, Hosts, etc.)
/// These do NOT depend on Tokio Runtime and should be singletons (Arc).
pub fn create_shared_plugins(
    config: &Config,
    #[cfg(target_os = "linux")]
    xdp_filter: Option<Arc<tokio::sync::Mutex<crate::bpf::DnsBpfFilter>>>,
) -> HashMap<String, AnyPlugin> {
    let mut registry = HashMap::new();

    #[cfg(target_os = "linux")]
    let xdp_cache_enabled = config
        .ebpf
        .as_ref()
        .and_then(|e| e.xdp_cache.as_ref())
        .map(|x| x.enabled)
        .unwrap_or(true);
    
    for (name, p_conf) in &config.plugins {
        let plugin: Option<AnyPlugin> = match p_conf {
            PluginType::Cache { size, fakeip_protection, upstreams, prefetch_if_ttl_less_than, serve_stale_ttl, recursive_mode, persist_file, persist_interval, .. } => {
                let prefetch_conf = if !upstreams.is_empty() {
                    Some((upstreams.clone(), *prefetch_if_ttl_less_than, *serve_stale_ttl))
                } else {
                    None
                };
                
                let mut recursive_backend = None;
                if *recursive_mode {
                     use crate::plugins::recursive_backend::RecursiveBackend;
                     recursive_backend = Some(Arc::new(RecursiveBackend::new()));
                }

                let mut cp = crate::plugins::cache::CachePlugin::new(
                    *size as u64, 
                    prefetch_conf, 
                    recursive_backend,
                    persist_file.clone(),
                    *persist_interval
                );
                cp.name = name.clone();
                cp.fakeip_protection = *fakeip_protection;

                #[cfg(target_os = "linux")]
                if let Some(filter) = &xdp_filter {
                    if xdp_cache_enabled {
                        // IMPORTANT: enable_xdp_cache MUST be called BEFORE set_xdp_filter
                        // so that the warmup task inside set_xdp_filter can trigger properly
                        cp.enable_xdp_cache(true);
                        cp.set_xdp_filter(filter.clone());
                    } else {
                        info!("⚠️ XDP cache disabled by config; kernel cache sync is OFF");
                    }
                }
                
                // Start persistence background task if configured
                let cp_arc = Arc::new(cp);
                if let Some(path) = persist_file.as_ref() {
                    cp_arc.clone().start_persistence_task();
                    info!("📦 Cache Plugin '{}' created with disk persistence ({})", name, path);
                } else {
                    info!("📦 Cache Plugin '{}' created (Shared)", name);
                }
                Some(AnyPlugin::Cache(cp_arc))
            },
            PluginType::Reject { rcode } => {
                use crate::plugins::reject::{RejectPlugin, RejectType};
                let reject_type = match rcode.as_str() {
                    "nxdomain" => RejectType::NxDomain,
                    "noerror" => RejectType::NoError,
                    "blackhole_v4" => RejectType::BlackholeV4,
                    "blackhole_v6" => RejectType::BlackholeV6,
                    ip => RejectType::CustomIp(ip.to_string()),
                };
                Some(AnyPlugin::Reject(Arc::new(RejectPlugin::new(name.clone(), reject_type))))
            },
            PluginType::Hosts { file } => {
                let path = std::path::PathBuf::from(file);
                match crate::plugins::hosts::HostsPlugin::load_from_file(path) {
                    Ok(mut p) => { 
                        p.name = name.clone(); 
                        info!("📂 Hosts Plugin '{}' loaded (Shared)", name);
                        Some(AnyPlugin::Hosts(Arc::new(p))) 
                    },
                    Err(e) => { error!("❌ Hosts {}: {}", name, e); None }
                }
            },
            PluginType::GeoSite { target, files, mark } => {
                let mut p = crate::plugins::geosite::GeoSitePlugin::new(target);
                p.name = name.clone();
                if let Some(m) = mark { p = p.with_mark(m); }
                
                for file in files {
                     if let Err(e) = p.load_from_file(file) {
                         error!("❌ GeoSite {}: Failed to load {}: {}", name, file, e);
                     }
                }
                info!("🌍 GeoSite Plugin '{}' loaded (Shared)", name);
                Some(AnyPlugin::GeoSite(Arc::new(p)))
            },
            PluginType::Ecs { auto, ipv4_netmask, ipv6_netmask, force_subnet } => {
                 let p = crate::plugins::ecs::EcsPlugin::new(
                     name.clone(),
                     *auto,
                     *ipv4_netmask,
                     *ipv6_netmask,
                     force_subnet.clone(),
                 );
                 Some(AnyPlugin::Ecs(Arc::new(p)))
            },
            PluginType::GeoIp { file, code, tag, mode, invert } => {
                let mode_enum = match mode.to_lowercase().as_str() {
                    "client" => crate::plugins::geoip::GeoIpMode::Client,
                    "response" | "" => crate::plugins::geoip::GeoIpMode::Response,
                    _ => {
                        error!("❌ GeoIp {}: Invalid mode '{}', defaulting to response", name, mode);
                        crate::plugins::geoip::GeoIpMode::Response
                    }
                };
                match crate::plugins::geoip::GeoIpPlugin::new(file, code, tag, mode_enum) {
                    Ok(p) => {
                         let mut p = p.with_invert(*invert);
                         p.name = name.clone();
                         info!("🗺️ GeoIp Plugin '{}' loaded (Shared)", name);
                         Some(AnyPlugin::GeoIp(Arc::new(p)))
                    },
                    Err(e) => { error!("❌ GeoIp {}: Failed to load MMDB {}: {}", name, file, e); None }
                }
            },
            PluginType::Matcher { files, mark } => {
                let p = crate::plugins::matcher::MatcherPlugin::new(
                    name.clone(),
                    files.clone(),
                    mark.clone(),
                );
                Some(AnyPlugin::Matcher(Arc::new(p)))
            },
            PluginType::QueryLog { file } => {
                match crate::plugins::query_log::QueryLogPlugin::new(Some(std::path::PathBuf::from(file)), true, true) {
                     Ok(mut p) => { p.name = name.clone(); Some(AnyPlugin::Log(Arc::new(p))) },
                     Err(e) => { error!("❌ QueryLog init failed: {}", e); None }
                }
            },
            PluginType::FakeIp { inet4_range, inet6_range } => {
                match crate::plugins::fakeip::FakeIpPlugin::new(name.clone(), inet4_range, inet6_range) {
                    Ok(p) => {
                        info!("🎭 FakeIP Plugin '{}' created (v4: {}, v6: {})", name, inet4_range, inet6_range);
                        Some(AnyPlugin::FakeIp(Arc::new(p)))
                    },
                    Err(e) => { error!("❌ FakeIP init failed: {}", e); None }
                }
            },
            PluginType::Dns64 { prefix, only_if_no_aaaa } => {
                match crate::plugins::dns64::Dns64Plugin::new(name.clone(), prefix.clone(), *only_if_no_aaaa) {
                    Ok(p) => {
                        info!("🔄 DNS64 Plugin '{}' created", name);
                        Some(AnyPlugin::Dns64(Arc::new(p)))
                    },
                    Err(e) => { error!("❌ DNS64 init failed: {}", e); None }
                }
            },
            PluginType::Dnssec { mode } => {
                match crate::plugins::dnssec::DnssecPlugin::new(name.clone(), mode.clone()) {
                    Ok(p) => {
                        info!("🔐 DNSSEC Plugin '{}' created (mode: {})", name, mode);
                        Some(AnyPlugin::Dnssec(Arc::new(p)))
                    },
                    Err(e) => { error!("❌ DNSSEC init failed: {}", e); None }
                }
            },
            PluginType::AdBlock { files } => {
                match crate::plugins::adblock::AdBlockPlugin::new(name.clone(), files.clone()) {
                     Ok(p) => {
                         info!("🛡️ AdBlock Plugin '{}' created", name);
                         Some(AnyPlugin::AdBlock(Arc::new(p)))
                     },
                     Err(e) => { error!("❌ AdBlock init failed: {}", e); None }
                }
            },
            PluginType::Ipv6Filter { mode, delay_aaaa_ms } => {
                match crate::plugins::ipv6_filter::Ipv6FilterPlugin::new(name.clone(), mode, *delay_aaaa_ms) {
                     Ok(p) => Some(AnyPlugin::Ipv6Filter(Arc::new(p))),
                     Err(e) => { error!("❌ Ipv6Filter init failed: {}", e); None }
                }
            },
            PluginType::Dga { entropy_threshold, min_len, dry_run } => {
                let p = crate::plugins::dga::DGAPlugin::new(
                    name.clone(),
                    *entropy_threshold,
                    *min_len,
                    *dry_run,
                );
                info!("🛡️ DGA Plugin '{}' created", name);
                Some(AnyPlugin::Dga(Arc::new(p)))
            },
            PluginType::IpMatcher { files, mark } => {
                let p = crate::plugins::ip_matcher::IpMatcherPlugin::new(
                    name.clone(),
                    files.clone(),
                    mark.clone(),
                );
                info!("🌐 IpMatcher Plugin '{}' created ({} rules)", name, p.rule_count());
                Some(AnyPlugin::IpMatcher(Arc::new(p)))
            },
            PluginType::SmartResolve { upstreams, probe_timeout_ms, probe_port, prefer_ipv4, max_ips_to_probe } => {
                match crate::plugins::smart_resolve::SmartResolvePlugin::new(
                    name.clone(),
                    upstreams.clone(),
                    *probe_timeout_ms,
                    *probe_port,
                    *prefer_ipv4,
                    *max_ips_to_probe,
                ) {
                    Ok(p) => {
                        info!("🚀 SmartResolve Plugin '{}' created ({} upstreams)", name, upstreams.len());
                        Some(AnyPlugin::SmartResolve(Arc::new(p)))
                    },
                    Err(e) => { error!("❌ SmartResolve init failed: {}", e); None }
                }
            },
            PluginType::Ttl { fixed, min, max } => {
                let p = crate::plugins::ttl::TtlPlugin::new(*fixed, *min, *max);
                // 简单的日志记录
                if let Some(f) = fixed {
                    info!("⏱️ TTL Plugin '{}' created (fixed: {}s)", name, f);
                } else {
                    info!("⏱️ TTL Plugin '{}' created (range: {:?}-{:?}s)", name, min, max);
                }
                Some(AnyPlugin::Ttl(Arc::new(p)))
            },
            PluginType::RateLimit { max_queries, window_secs } => {
                info!("🛡️ RateLimit Plugin '{}' created ({} queries/{}s)", name, max_queries, window_secs);
                let p = crate::plugins::ratelimit::RateLimitPlugin::new(*max_queries, *window_secs);
                Some(AnyPlugin::RateLimit(Arc::new(p)))
            },
            PluginType::AliApi { account_id, access_key_id, access_key_secret } => {
                info!("🌐 AliAPI Plugin '{}' created (account: {})", name, account_id);
                let p = crate::plugins::aliapi::AliApiPlugin::new(
                    account_id.clone(),
                    access_key_id.clone(),
                    access_key_secret.clone(),
                );
                Some(AnyPlugin::AliApi(Arc::new(p)))
            },
            // Runtime-dependent plugins (Forward) or Composite plugins (Fallback, Sequence) are skipped here.
            _ => None 
        };

        if let Some(p) = plugin {
            registry.insert(name.clone(), p);
        }
    }
    registry
}

/// Phase 2: Create execution registry on a specific Runtime.
/// - Inherits shared plugins.
/// - Creates Forwarders (I/O bound).
/// - Assembles Fallbacks and Sequences.
/// IMPORTANT: This MUST be an async fn so that reqwest::Client can detect the current Runtime.
pub async fn create_runtime_registry(
    config: &Config,
    proxy_state: Arc<AtomicBool>,
    discovered_socks_port: Option<u16>,
    shared_plugins: &HashMap<String, AnyPlugin>,
) -> PluginRegistry {
    // Start with shared plugins
    let mut plugin_registry = shared_plugins.clone();
    
    // Find cache handle for API (if any)
    let mut api_cache_handle = None;
    for p in plugin_registry.values() {
        if let AnyPlugin::Cache(c) = p {
            api_cache_handle = Some(c.clone());
            break;
        }
    }

    // 1. Instantiate Runtime-Specific Plugins (Forward)
    for (name, p_conf) in &config.plugins {
        debug!("🔧 Inspecting plugin '{}': {:?}", name, p_conf);
        if let PluginType::Forward { upstreams, concurrent, strategy, .. } = p_conf {
             // ... forward creation logic ...
             let mut final_upstreams = upstreams.clone();
             if let Some(port) = discovered_socks_port {
                  for u in &mut final_upstreams {
                      if let Some(s) = &u.socks5 {
                          if s == "auto" {
                              debug!("🔄 Configuring upstream {} to use discovered SOCKS port: {}", u.addr, port);
                              u.socks5 = Some(format!("127.0.0.1:{}", port));
                          }
                      }
                  }
             }

             let mut fp = crate::plugins::forward::ForwardPlugin::new(
                 name.clone(),
                 final_upstreams,
                 strategy.clone(),
                 concurrent.unwrap_or(2)
             );
             fp.proxy_status = Some(proxy_state.clone());
             
             // Pre-warm DoH/DoT connections (fire and forget)
             fp.warmup().await;
             
             info!("🚀 Forward Plugin '{}' created (Runtime Local)", name);
             plugin_registry.insert(name.clone(), AnyPlugin::Forward(Arc::new(fp)));
        }

        if let PluginType::SmartForward {
            local,
            fakeip,
            local_upstreams,
            fakeip_upstreams,
            local_strategy,
            fakeip_strategy,
            local_concurrent,
            fakeip_concurrent,
            local_timeout_ms,
            fakeip_timeout_ms,
            local_fallback_upstreams,
            local_fallback_strategy,
            local_fallback_concurrent,
            local_fallback_timeout_ms,
            avoid_fakeip_on_domestic,
            domestic_suffixes,
            ip_matcher,
            geoip,
            learning_cache_file,  // [新增] Learning Cache 持久化
        } = p_conf {
             if let Some(AnyPlugin::GeoIp(g)) = plugin_registry.get(geoip) {
                 let mut local_upstreams = local_upstreams.clone();
                 let mut fakeip_upstreams = fakeip_upstreams.clone();
                 if let Some(port) = discovered_socks_port {
                     for u in &mut local_upstreams {
                         if let Some(s) = &u.socks5 {
                             if s == "auto" {
                                 debug!("🔄 SmartForward local upstream {} uses discovered SOCKS port: {}", u.addr, port);
                                 u.socks5 = Some(format!("127.0.0.1:{}", port));
                             }
                         }
                     }
                     for u in &mut fakeip_upstreams {
                         if let Some(s) = &u.socks5 {
                             if s == "auto" {
                                 debug!("🔄 SmartForward fakeip upstream {} uses discovered SOCKS port: {}", u.addr, port);
                                 u.socks5 = Some(format!("127.0.0.1:{}", port));
                             }
                         }
                     }
                 }
                 
                 let ip_matcher_plugin = if let Some(matcher_name) = ip_matcher {
                     if let Some(AnyPlugin::IpMatcher(m)) = plugin_registry.get(matcher_name) {
                         Some(m.clone())
                     } else {
                         error!("SmartForward '{}' references missing IpMatcher '{}'", name, matcher_name);
                         None
                     }
                 } else {
                     None
                 };
                 
                let sp = crate::plugins::smart_forward::SmartForwardPlugin::new(
                    name.clone(),
                    local.clone(),
                    fakeip.clone(),
                    local_upstreams,
                    fakeip_upstreams,
                    local_strategy.clone(),
                    fakeip_strategy.clone(),
                    *local_concurrent,
                    *fakeip_concurrent,
                    *local_timeout_ms,
                    *fakeip_timeout_ms,
                    local_fallback_upstreams.clone(),
                    local_fallback_strategy.clone(),
                    *local_fallback_concurrent,
                    *local_fallback_timeout_ms,
                    *avoid_fakeip_on_domestic,
                    domestic_suffixes.clone(),
                    ip_matcher_plugin,
                    g.clone(),
                    learning_cache_file.clone(),  // [NEW] Persistence file
                ).await;
                 match sp {
                     Ok(p) => {
                         let plugin_arc = Arc::new(p);
                         // Start background persistence task
                         plugin_arc.clone().start_persistence_task();
                         info!("🧠 Smart Forward Plugin '{}' created", name);
                         plugin_registry.insert(name.clone(), AnyPlugin::SmartForward(plugin_arc));
                     },
                     Err(e) => error!("❌ Failed to create SmartForward '{}': {}", name, e),
                 }
             } else {
                 error!("❌ SmartForward '{}' depends on missing GeoIp plugin '{}'", name, geoip);
             }
        }
    }

    // 2. Initialize Fallback/Sequence (Composite)
    // ... Fallback ...
    for (name, p_conf) in &config.plugins {
        if let PluginType::Fallback { primary, secondary, threshold, always_standby } = p_conf {
             // ...
             let primary_plugin = plugin_registry.get(primary).cloned();
             let secondary_plugin = plugin_registry.get(secondary).cloned();
            
             if let (Some(p), Some(s)) = (primary_plugin, secondary_plugin) {
                 let fallback = crate::plugins::fallback::FallbackPlugin::new(
                     name.clone(),
                     Arc::new(p),
                     Arc::new(s),
                     *threshold,
                     *always_standby,
                 );
                 plugin_registry.insert(name.clone(), AnyPlugin::Fallback(Arc::new(fallback)));
             } else {
                 error!("❌ Fallback '{}': deps missing", name);
             }
        }
    }
    
    // ... Sequences (Multi-pass resolution for dependencies) ...
    let mut entry_points: HashMap<String, AnyPlugin> = HashMap::new();
    let mut pending_sequences: Vec<_> = config.sequences.iter().collect();
    let mut loop_protect = 0;
    
    while !pending_sequences.is_empty() {
        let mut progress = false;
        let mut next_pending = Vec::new();

        for (seq_name, steps) in pending_sequences {
            // Check if all dependencies are ready
            let mut ready = true;
            let mut compiled_steps = Vec::new();
            
            for step_conf in steps {
                if let Some(p) = plugin_registry.get(&step_conf.exec) {
                    compiled_steps.push(Step {
                        conditions: step_conf.matches.clone(),
                        plugin: p.clone(),
                    });
                } else {
                    ready = false;
                    break;
                }
            }

            if ready {
                let seq = Sequence {
                    name: seq_name.clone(),
                    steps: compiled_steps,
                    matchers_registry: plugin_registry.clone(),
                };
                let any_seq = AnyPlugin::Sequence(Arc::new(seq));
                
                plugin_registry.insert(seq_name.clone(), any_seq.clone());
                entry_points.insert(seq_name.clone(), any_seq);
                progress = true;
                debug!("🔗 Sequence '{}' resolved and built.", seq_name);
            } else {
                next_pending.push((seq_name, steps));
            }
        }

        if !progress {
            loop_protect += 1;
            // Allow a few passes (depth of dependency chain)
            if loop_protect > 20 {
                for (name, steps) in &next_pending {
                    // Log specifically which dependency is missing for debugging
                    for step in *steps {
                        if !plugin_registry.contains_key(&step.exec) {
                            error!("❌ Sequence '{}' stuck: missing dependency '{}'", name, step.exec);
                        }
                    }
                }
                break;
            }
        }
        pending_sequences = next_pending;
    }
    
    PluginRegistry {
        plugins: plugin_registry,
        entry_points,
        api_cache_handle,
    }
}
