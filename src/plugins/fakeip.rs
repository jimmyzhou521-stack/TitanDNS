use crate::core::context::Context;
use crate::core::plugin::Plugin;
use anyhow::Result;
use tracing::warn;

#[derive(Debug)]
pub struct FakeIpPlugin {
    pub name: String,
    pub _inet4_range: String,
    pub _inet6_range: String,
    warned: std::sync::atomic::AtomicBool,
}

impl FakeIpPlugin {
    // Factory passes &String to us
    pub fn new(name: String, inet4_range: &String, inet6_range: &String) -> Result<Self> {
        warn!("⚠️ FakeIpPlugin '{}' is a PLACEHOLDER implementation!", name);
        warn!("   FakeIP logic is handled by sing-box integration, not this plugin.");
        warn!("   If you need standalone FakeIP, consider using upstream_fakeip with correct config.");
        Ok(Self {
            name,
            _inet4_range: inet4_range.to_string(),
            _inet6_range: inet6_range.to_string(),
            warned: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl Plugin for FakeIpPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, _ctx: &mut Context) -> Result<()> {
        // Log once per instance to avoid log spam
        if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
            warn!("⚠️ FakeIpPlugin::handle() called but is NO-OP! Use sing-box for FakeIP.");
        }
        Ok(())
    }
}
