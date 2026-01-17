// Fallback Plugin: Primary/Secondary failover
// Behavior modeled after mosdns fallback:
// - Secondary starts after threshold or when primary fails.
// - When always_standby=true, secondary runs immediately but only used on failure/timeout.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::plugins::AnyPlugin;

const DEFAULT_PARALLEL_TIMEOUT: Duration = Duration::from_secs(5);

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

    fn ctx_has_response(ctx: &Context) -> bool {
        ctx.response.is_some() || ctx.raw_response.is_some()
    }

    fn apply_ctx(from: Context, to: &mut Context) {
        to.response = from.response;
        to.raw_response = from.raw_response;
        to.tags = from.tags;
        to.abort = from.abort;
        to.min_ttl = from.min_ttl;
        to.post_process_hooks = from.post_process_hooks;
    }

    async fn handle_fallback(&self, ctx: &mut Context) -> Result<()> {
        let primary = self.primary.clone();
        let secondary = self.secondary.clone();
        let threshold = self.threshold;
        let always_standby = self.always_standby;

        let run = |name: String,
                   role: &'static str,
                   plugin: Arc<AnyPlugin>,
                   mut run_ctx: Context| async move {
            let result = timeout(DEFAULT_PARALLEL_TIMEOUT, plugin.handle(&mut run_ctx)).await;
            match result {
                Ok(Ok(())) if Self::ctx_has_response(&run_ctx) => {
                    debug!("Fallback '{}': {} succeeded", name, role);
                    Some(run_ctx)
                }
                Ok(Ok(())) => {
                    warn!("Fallback '{}': {} returned no response", name, role);
                    None
                }
                Ok(Err(e)) => {
                    warn!("Fallback '{}': {} failed: {}", name, role, e);
                    None
                }
                Err(_) => {
                    warn!(
                        "Fallback '{}': {} timed out ({}ms)",
                        name,
                        role,
                        DEFAULT_PARALLEL_TIMEOUT.as_millis()
                    );
                    None
                }
            }
        };

        let primary_ctx = ctx.clone();
        let mut primary_fut = Box::pin(run(self.name.clone(), "Primary", primary, primary_ctx));
        let mut primary_done = false;

        if !always_standby {
            let delay = tokio::time::sleep(threshold);
            tokio::pin!(delay);
            tokio::select! {
                res = &mut primary_fut => {
                    primary_done = true;
                    if let Some(success_ctx) = res {
                        Self::apply_ctx(success_ctx, ctx);
                        return Ok(());
                    }
                }
                _ = &mut delay => {
                    // threshold reached, start secondary
                }
            }

            if primary_done {
                let secondary_ctx = ctx.clone();
                if let Some(success_ctx) =
                    run(self.name.clone(), "Secondary", secondary, secondary_ctx).await
                {
                    Self::apply_ctx(success_ctx, ctx);
                    return Ok(());
                }
                return Err(anyhow::anyhow!("Both upstreams failed"));
            }

            let secondary_ctx = ctx.clone();
            let mut secondary_fut =
                Box::pin(run(self.name.clone(), "Secondary", secondary, secondary_ctx));
            let mut secondary_done = false;

            loop {
                tokio::select! {
                    res = &mut primary_fut, if !primary_done => {
                        primary_done = true;
                        if let Some(success_ctx) = res {
                            Self::apply_ctx(success_ctx, ctx);
                            return Ok(());
                        }
                    }
                    res = &mut secondary_fut, if !secondary_done => {
                        secondary_done = true;
                        if let Some(success_ctx) = res {
                            Self::apply_ctx(success_ctx, ctx);
                            return Ok(());
                        }
                    }
                }

                if primary_done && secondary_done {
                    break;
                }
            }

            return Err(anyhow::anyhow!("Both upstreams failed"));
        }

        let secondary_ctx = ctx.clone();
        let mut secondary_fut =
            Box::pin(run(self.name.clone(), "Secondary", secondary, secondary_ctx));
        let mut secondary_cached: Option<Option<Context>> = None;
        let mut allow_secondary = false;
        let delay = tokio::time::sleep(threshold);
        tokio::pin!(delay);

        loop {
            tokio::select! {
                res = &mut primary_fut, if !primary_done => {
                    primary_done = true;
                    if let Some(success_ctx) = res {
                        Self::apply_ctx(success_ctx, ctx);
                        return Ok(());
                    }
                    allow_secondary = true;
                    if let Some(Some(success_ctx)) = secondary_cached.take() {
                        Self::apply_ctx(success_ctx, ctx);
                        return Ok(());
                    }
                }
                res = &mut secondary_fut, if secondary_cached.is_none() => {
                    secondary_cached = Some(res);
                    if allow_secondary {
                        if let Some(Some(success_ctx)) = secondary_cached.take() {
                            Self::apply_ctx(success_ctx, ctx);
                            return Ok(());
                        }
                    }
                }
                _ = &mut delay, if !allow_secondary => {
                    allow_secondary = true;
                    if let Some(Some(success_ctx)) = secondary_cached.take() {
                        Self::apply_ctx(success_ctx, ctx);
                        return Ok(());
                    }
                }
            }

            let secondary_done = secondary_cached.is_some();
            if primary_done && secondary_done && allow_secondary {
                break;
            }
        }

        Err(anyhow::anyhow!("Both upstreams failed"))
    }
}

impl Plugin for FallbackPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        self.handle_fallback(ctx).await
    }
}
