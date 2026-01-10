// Fallback Plugin: Primary/Secondary failover
// If primary upstream times out, automatically switch to secondary

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::plugins::AnyPlugin;

/// FallbackPlugin provides automatic failover from primary to secondary upstream
#[derive(Clone)]
pub struct FallbackPlugin {
    pub name: String,
    primary: Arc<AnyPlugin>,
    secondary: Arc<AnyPlugin>,
    threshold: Duration,
    always_standby: bool,
}

impl std::fmt::Debug for FallbackPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackPlugin")
            .field("name", &self.name)
            .field("threshold_ms", &self.threshold.as_millis())
            .field("always_standby", &self.always_standby)
            .finish()
    }
}

impl FallbackPlugin {
    /// Create a new FallbackPlugin
    pub fn new(
        name: String,
        primary: Arc<AnyPlugin>,
        secondary: Arc<AnyPlugin>,
        threshold_ms: u64,
        always_standby: bool,
    ) -> Self {
        Self {
            name,
            primary,
            secondary,
            threshold: Duration::from_millis(threshold_ms),
            always_standby,
        }
    }
}

impl Plugin for FallbackPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if self.always_standby {
            // Parallel mode: query both and use first response
            self.handle_parallel(ctx).await
        } else {
            // Sequential mode: primary first, then secondary on timeout
            self.handle_sequential(ctx).await
        }
    }
}

impl FallbackPlugin {
    /// Sequential mode: try primary first, fallback to secondary on timeout
    async fn handle_sequential(&self, ctx: &mut Context) -> Result<()> {
        debug!("Fallback '{}': Trying primary...", self.name);
        
        // Clone context for primary attempt
        let mut primary_ctx = ctx.clone();
        
        // Try primary with timeout
        match timeout(self.threshold, self.primary.handle(&mut primary_ctx)).await {
            Ok(Ok(())) => {
                // Primary succeeded
                if primary_ctx.response.is_some() {
                    debug!("Fallback '{}': Primary succeeded", self.name);
                    ctx.response = primary_ctx.response;
                    ctx.tags = primary_ctx.tags;
                    return Ok(());
                }
            }
            Ok(Err(e)) => {
                warn!("Fallback '{}': Primary failed: {}", self.name, e);
            }
            Err(_) => {
                warn!("Fallback '{}': Primary timed out ({}ms)", self.name, self.threshold.as_millis());
            }
        }
        
        // Fallback to secondary
        debug!("Fallback '{}': Trying secondary...", self.name);
        match self.secondary.handle(ctx).await {
            Ok(()) => {
                debug!("Fallback '{}': Secondary succeeded", self.name);
                Ok(())
            }
            Err(e) => {
                warn!("Fallback '{}': Secondary also failed: {}", self.name, e);
                Err(e)
            }
        }
    }

    /// Parallel mode: query both simultaneously, use first response
    async fn handle_parallel(&self, ctx: &mut Context) -> Result<()> {
        debug!("Fallback '{}': Querying both upstreams in parallel...", self.name);
        
        let mut primary_ctx = ctx.clone();
        let mut secondary_ctx = ctx.clone();
        
        // Start both queries in parallel
        let primary_fut = self.primary.handle(&mut primary_ctx);
        let secondary_fut = self.secondary.handle(&mut secondary_ctx);
        
        tokio::select! {
            primary_result = primary_fut => {
                match primary_result {
                    Ok(()) if primary_ctx.response.is_some() => {
                        debug!("Fallback '{}': Primary won race", self.name);
                        ctx.response = primary_ctx.response;
                        ctx.tags = primary_ctx.tags;
                        return Ok(());
                    }
                    _ => {}
                }
            }
            secondary_result = secondary_fut => {
                match secondary_result {
                    Ok(()) if secondary_ctx.response.is_some() => {
                        debug!("Fallback '{}': Secondary won race", self.name);
                        ctx.response = secondary_ctx.response;
                        ctx.tags = secondary_ctx.tags;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
        
        // If we get here, neither succeeded immediately, wait for the other
        warn!("Fallback '{}': Both upstreams slow or failed", self.name);
        Err(anyhow::anyhow!("Both upstreams failed"))
    }
}
