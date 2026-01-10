use anyhow::Result;
use std::sync::Arc;
use crate::core::context::Context;

/// The Core Trait for all TitanDNS functional blocks.
pub trait Plugin: Send + Sync + std::fmt::Debug {
    /// Return the name/type of the plugin
    fn name(&self) -> &str;

    /// Process the request (The "Inbound" path)
    async fn handle(&self, ctx: &mut Context) -> Result<()>;

    /// Process the response (The "Outbound" path / Hook)
    /// This is called after a response is generated but before it's sent to the user.
    /// Useful for: Caching (Write-back), Logging, Auditing.
    async fn on_response(&self, _ctx: &mut Context) -> Result<()> {
        Ok(())
    }

    /// Check if this plugin matches a given query name (For Matcher plugins)
    fn is_match(&self, _qname: &str) -> bool {
        false
    }
}

/// Type alias for a shared plugin object (Arc pointer).
pub type ArcPlugin = Arc<dyn Plugin>;
