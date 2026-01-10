use std::path::PathBuf;
use tokio::net::TcpStream;
use tracing::{info, warn};
use std::fs;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Sing-box Integration Module
/// This module is responsible for detecting Sing-box presence, parsing its config,
/// and monitoring its health to prevent DNS deadlocks.
pub struct SingBoxMonitor {
    config_path: Option<PathBuf>,
    pub socks_port: u16,
    is_alive: bool,
    shared_status: Option<Arc<AtomicBool>>,
}



impl SingBoxMonitor {
    pub fn new(shared_status: Option<Arc<AtomicBool>>) -> Self {
        Self { 
            config_path: None, 
            socks_port: 7891, // Default guess, can be overridden by auto-discovery
            is_alive: false,
            shared_status,
        }
    }

    /// Try to auto-discover sing-box config from common paths
    pub fn auto_discover(&mut self) {
        let common_paths = [
            "./config.json", // Local directory first
            "C:/Program Files/sing-box/config.json",
            "C:/ProgramData/sing-box/config.json",
            "/etc/sing-box/config.json",
            "../sing-box/config.json", 
            "../mosdns/sing-box/config.json",
        ];

        for path in common_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                info!("🔎 Found Sing-box config at: {:?}", p);
                self.config_path = Some(p.clone());

                // Parse JSON and extract 'inbounds' -> 'socks' port
                if let Ok(content) = fs::read_to_string(&p) {
                    if let Ok(v) = serde_json::from_str::<Value>(&content) {
                        if let Some(inbounds) = v["inbounds"].as_array() {
                            for inbound in inbounds {
                                let type_str = inbound["type"].as_str().unwrap_or("");
                                // Look for 'socks' or 'mixed' (which includes socks)
                                if type_str == "socks" || type_str == "mixed" {
                                    if let Some(port) = inbound["listen_port"].as_u64() {
                                        info!("✅ Auto-detected Sing-box SOCKS port: {}", port);
                                        self.socks_port = port as u16;
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
                return;
            }
        }
        warn!("⚠️ Sing-box config not found. Using default port {}", self.socks_port);
    }

    /// Run the monitoring loop
    pub async fn run_monitor_loop(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await; 
            let alive = self.check_health().await;
            if let Some(status) = &self.shared_status {
                status.store(alive, Ordering::Relaxed);
            }
        }
    }

    /// Active Health Check using TCP connect with Timeout
    pub async fn check_health(&mut self) -> bool {
        let addr = format!("127.0.0.1:{}", self.socks_port);
        match tokio::time::timeout(Duration::from_millis(1000), TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                if !self.is_alive {
                    info!("✅ Sing-box is ALIVE connection accepted on {}", self.socks_port);
                }
                self.is_alive = true;
                true
            }
            _ => {
                if self.is_alive {
                    warn!("🔥 Sing-box is DOWN (Connection Refused/Timeout on {})! Engaging Emergency Protocols.", self.socks_port);
                }
                self.is_alive = false;
                false
            }
        }
    }
}
