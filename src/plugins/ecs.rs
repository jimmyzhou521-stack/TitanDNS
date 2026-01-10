use anyhow::Result;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::debug;
use hickory_proto::op::Edns;
use hickory_proto::rr::rdata::opt::{EdnsOption, ClientSubnet};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

#[derive(Clone, Debug)]
pub struct EcsPlugin {
    pub name: String,
    pub auto: bool,
    pub v4_mask: u8,
    pub v6_mask: u8,
    pub force_subnet: Option<IpAddr>,
}

impl EcsPlugin {
    pub fn new(name: String, auto: bool, v4: Option<u8>, v6: Option<u8>, force: Option<String>) -> Self {
        let force_ip = force.and_then(|s| {
            // Remove CIDR suffix if present for parsing as IP
            let ip_str = s.split('/').next().unwrap_or(&s);
            IpAddr::from_str(ip_str).ok()
        });

        Self {
            name,
            auto,
            v4_mask: v4.unwrap_or(24),
            v6_mask: v6.unwrap_or(56),
            force_subnet: force_ip,
        }
    }

    fn apply_ecs(&self, ctx: &mut Context, ip: IpAddr) {
        debug!("🌐 Injecting ECS: {}/{}", ip, self.v4_mask);

        let edns = ctx.request.extensions_mut().get_or_insert_with(Edns::new);
        let options = edns.options_mut();

        // Use ClientSubnet struct wrapper
        let (mask, scope) = match ip {
            IpAddr::V4(_) => (self.v4_mask, 0),
            IpAddr::V6(_) => (self.v6_mask, 0),
        };

        // ClientSubnet::new(address, source_prefix, scope_prefix)
        let subnet = ClientSubnet::new(ip, mask, scope);
        options.insert(EdnsOption::Subnet(subnet));
    }
}

impl Plugin for EcsPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let target_ip = if let Some(ip) = self.force_subnet {
            Some(ip)
        } else if self.auto {
            let client_ip = ctx.client_addr.ip();
            if client_ip.is_loopback() {
                None
            } else {
                Some(client_ip)
            }
        } else {
            None
        };

        if let Some(ip) = target_ip {
            self.apply_ecs(ctx, ip);
        }

        Ok(())
    }
}
