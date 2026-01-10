use anyhow::Result;
use std::sync::Arc;
use crate::core::context::Context;
use crate::core::plugin::Plugin;

pub mod cache;
pub mod forward;
pub mod adaptive_pool;
pub mod cache_warmup;
pub mod cache_smart_refresh;
pub mod sequence;
pub mod reject;
pub mod query_log;
pub mod hosts;
pub mod geosite;
pub mod geoip;
pub mod matcher;
pub mod fallback;
pub mod ecs;
pub mod recursive_backend;
pub mod smart_forward;
pub mod fakeip;
pub mod dns64;
pub mod dnssec;
pub mod adblock;
pub mod ipv6_filter;
pub mod dga;
pub mod ip_matcher;
pub mod smart_resolve;
pub mod aliapi;
pub mod ratelimit;
pub mod ttl;

use self::cache::CachePlugin;
use self::forward::ForwardPlugin;
use self::smart_forward::SmartForwardPlugin;
use self::sequence::Sequence;
use self::reject::RejectPlugin;
use self::query_log::QueryLogPlugin;
use self::hosts::HostsPlugin;
use self::geosite::GeoSitePlugin;
use self::geoip::GeoIpPlugin;
use self::matcher::MatcherPlugin;
use self::fallback::FallbackPlugin;
use self::ecs::EcsPlugin;
use self::fakeip::FakeIpPlugin;
use self::dns64::Dns64Plugin;
use self::dnssec::DnssecPlugin;
use self::adblock::AdBlockPlugin;
use self::ipv6_filter::Ipv6FilterPlugin;
use self::dga::DGAPlugin;
use self::ip_matcher::IpMatcherPlugin;
use self::smart_resolve::SmartResolvePlugin;
use self::aliapi::AliApiPlugin;
use self::ratelimit::RateLimitPlugin;
use self::ttl::TtlPlugin;

/// Static Dispatch Wrapper for all Plugins
#[derive(Clone, Debug)]
pub enum AnyPlugin {
    Cache(Arc<CachePlugin>),
    Forward(Arc<ForwardPlugin>),
    SmartForward(Arc<SmartForwardPlugin>),
    Sequence(Arc<Sequence>),
    Reject(Arc<RejectPlugin>),
    Log(Arc<QueryLogPlugin>),
    Hosts(Arc<HostsPlugin>),
    GeoSite(Arc<GeoSitePlugin>),
    GeoIp(Arc<GeoIpPlugin>),
    Matcher(Arc<MatcherPlugin>),
    Fallback(Arc<FallbackPlugin>),
    Ecs(Arc<EcsPlugin>),
    FakeIp(Arc<FakeIpPlugin>),
    Dns64(Arc<Dns64Plugin>),
    Dnssec(Arc<DnssecPlugin>),
    AdBlock(Arc<AdBlockPlugin>),
    Ipv6Filter(Arc<Ipv6FilterPlugin>),
    Dga(Arc<DGAPlugin>),
    IpMatcher(Arc<IpMatcherPlugin>),
    SmartResolve(Arc<SmartResolvePlugin>),
    AliApi(Arc<AliApiPlugin>),
    RateLimit(Arc<RateLimitPlugin>),
    Ttl(Arc<TtlPlugin>),
}

impl Plugin for AnyPlugin {
    fn name(&self) -> &str {
        match self {
            AnyPlugin::Cache(p) => p.name(),
            AnyPlugin::Forward(p) => p.name(),
            AnyPlugin::SmartForward(p) => p.name(),
            AnyPlugin::Sequence(p) => p.name(),
            AnyPlugin::Reject(p) => p.name(),
            AnyPlugin::Log(p) => p.name(),
            AnyPlugin::Hosts(p) => p.name(),
            AnyPlugin::GeoSite(p) => p.name(),
            AnyPlugin::GeoIp(p) => p.name(),
            AnyPlugin::Matcher(p) => p.name(),
            AnyPlugin::Fallback(p) => p.name(),
            AnyPlugin::Ecs(p) => p.name(),
            AnyPlugin::FakeIp(p) => p.name(),
            AnyPlugin::Dns64(p) => p.name(),
            AnyPlugin::Dnssec(p) => p.name(),
            AnyPlugin::AdBlock(p) => p.name(),
            AnyPlugin::Ipv6Filter(p) => p.name(),
            AnyPlugin::Dga(p) => p.name(),
            AnyPlugin::IpMatcher(p) => p.name(),
            AnyPlugin::SmartResolve(p) => p.name(),
            AnyPlugin::AliApi(p) => p.name(),
            AnyPlugin::RateLimit(p) => p.name(),
            AnyPlugin::Ttl(p) => p.name(),
        }
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        match self {
            AnyPlugin::Cache(p) => p.handle(ctx).await,
            AnyPlugin::Forward(p) => p.handle(ctx).await,
            AnyPlugin::SmartForward(p) => p.handle(ctx).await,
            AnyPlugin::Sequence(p) => Box::pin(p.handle(ctx)).await,
            AnyPlugin::Reject(p) => p.handle(ctx).await,
            AnyPlugin::Log(p) => p.handle(ctx).await,
            AnyPlugin::Hosts(p) => p.handle(ctx).await,
            AnyPlugin::GeoSite(p) => p.handle(ctx).await,
            AnyPlugin::GeoIp(p) => p.handle(ctx).await,
            AnyPlugin::Matcher(p) => p.handle(ctx).await,
            AnyPlugin::Fallback(p) => Box::pin(p.handle(ctx)).await,
            AnyPlugin::Ecs(p) => p.handle(ctx).await,
            AnyPlugin::FakeIp(p) => p.handle(ctx).await,
            AnyPlugin::Dns64(p) => p.handle(ctx).await,
            AnyPlugin::Dnssec(p) => p.handle(ctx).await,
            AnyPlugin::AdBlock(p) => p.handle(ctx).await,
            AnyPlugin::Ipv6Filter(p) => p.handle(ctx).await,
            AnyPlugin::Dga(p) => p.handle(ctx).await,
            AnyPlugin::IpMatcher(p) => p.handle(ctx).await,
            AnyPlugin::SmartResolve(p) => p.handle(ctx).await,
            AnyPlugin::AliApi(p) => p.handle(ctx).await,
            AnyPlugin::RateLimit(p) => p.handle(ctx).await,
            AnyPlugin::Ttl(p) => p.handle(ctx).await,
        }
    }

    async fn on_response(&self, ctx: &mut Context) -> Result<()> {
        match self {
            AnyPlugin::Cache(p) => p.on_response(ctx).await,
            AnyPlugin::Forward(p) => p.on_response(ctx).await,
            AnyPlugin::SmartForward(_p) => Ok(()), // No post-processing needed
            AnyPlugin::Sequence(p) => p.on_response(ctx).await,
            AnyPlugin::Reject(p) => p.on_response(ctx).await,
            AnyPlugin::Log(p) => p.on_response(ctx).await,
            AnyPlugin::Hosts(p) => p.on_response(ctx).await,
            AnyPlugin::GeoSite(p) => p.on_response(ctx).await,
            AnyPlugin::GeoIp(p) => p.on_response(ctx).await,
            AnyPlugin::Matcher(_) => Ok(()),
            AnyPlugin::Fallback(_) => Ok(()),
            AnyPlugin::Ecs(_) => Ok(()),
            AnyPlugin::FakeIp(_) => Ok(()),
            AnyPlugin::Dns64(_) => Ok(()),
            AnyPlugin::Dnssec(p) => p.on_response(ctx).await,
            AnyPlugin::AdBlock(_) => Ok(()),
            AnyPlugin::Ipv6Filter(_) => Ok(()),
            AnyPlugin::Dga(_) => Ok(()),
            AnyPlugin::IpMatcher(_) => Ok(()),
            AnyPlugin::SmartResolve(_) => Ok(()),
            AnyPlugin::AliApi(_) => Ok(()),
            AnyPlugin::RateLimit(_) => Ok(()),
            AnyPlugin::Ttl(_) => Ok(()),
        }
    }
}
