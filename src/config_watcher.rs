// Configuration Hot Reload Support
// Allows reloading configuration without restarting the service

#![allow(dead_code)] // Framework implementation

use anyhow::Result;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use tokio::sync::mpsc;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn, error};

pub struct ConfigWatcher {
    config_path: String,
    reload_count: Arc<AtomicU64>,
}

impl ConfigWatcher {
    pub fn new(config_path: String) -> Self {
        Self {
            config_path,
            reload_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start watching config file for changes
    pub async fn watch<F>(&self, mut on_reload: F) -> Result<()>
    where
        F: FnMut() -> Result<()> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();
        let config_path_buf = std::path::PathBuf::from(&config_path);
        let config_filename = config_path_buf
            .file_name()
            .map(|f| f.to_os_string());
        let reload_count = self.reload_count.clone();

        // Spawn file watcher in separate thread
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    tracing::error!("Failed to create tokio runtime for config watcher: {}", e);
                    return;
                }
            };
            rt.block_on(async move {
                let (event_tx, mut event_rx) = mpsc::channel(1);

                let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = event_tx.try_send(event);
                    }
                }) {
                    Ok(w) => w,
                    Err(e) => {
                        error!("Failed to create file watcher: {}", e);
                        return;
                    }
                };

                // Watch the config directory (not the file itself, as editors may replace files)
                let config_dir = Path::new(&config_path).parent().unwrap_or(Path::new("."));
                if let Err(e) = watcher.watch(config_dir, RecursiveMode::NonRecursive) {
                    error!("Failed to watch config directory: {}", e);
                    return;
                }

                info!("📡 Config watcher started for: {}", config_path);

                while let Some(event) = event_rx.recv().await {
                    // Only process modify/create/remove events for our config file
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                        let matched = event.paths.iter().any(|p| {
                            if p == &config_path_buf {
                                return true;
                            }
                            match (&config_filename, p.file_name()) {
                                (Some(cfg), Some(name)) => cfg == name,
                                _ => false,
                            }
                        });

                        if matched {
                            info!("🔄 Config file changed, triggering reload...");
                            let _ = tx.send(()).await;
                        }
                    }
                }
            });
        });

        // Handle reload events
        while let Some(_) = rx.recv().await {
            // Small delay to ensure file write is complete
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            match on_reload() {
                Ok(()) => {
                    let count = reload_count.fetch_add(1, Ordering::SeqCst) + 1;
                    info!("✅ Configuration reloaded successfully (reload #{})", count);
                }
                Err(e) => {
                    warn!("❌ Configuration reload failed: {}", e);
                    warn!("    Continuing with previous configuration");
                }
            }
        }

        Ok(())
    }

    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_watcher_creation() {
        let watcher = ConfigWatcher::new("config.yaml".to_string());
        assert_eq!(watcher.reload_count(), 0);
    }

    #[tokio::test]
    #[ignore] // Requires file system
    async fn test_config_reload() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_string_lossy().to_string();

        writeln!(temp_file, "test: value1").unwrap();
        temp_file.flush().unwrap();

        let watcher = ConfigWatcher::new(path.clone());
        let count = Arc::new(AtomicU64::new(0));
        let count_clone = count.clone();

        let handle = tokio::spawn(async move {
            let _ = watcher.watch(move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }).await;
        });

        // Give watcher time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Modify file
        fs::write(&path, "test: value2").unwrap();

        // Give watcher time to detect change
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Verify reload was triggered
        assert!(count.load(Ordering::SeqCst) > 0);

        handle.abort();
    }
}
