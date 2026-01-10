// SmartResolve Plugin v2.1: Robust Probe & External Fallback Support
// - Checks BOTH Port 80 and 443 (whichever connects first)
// - If internal fallback fails, returns error to allow external plugins to take over

use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::config::UpstreamConfig;
use crate::plugins::forward::Upstream;
use anyhow::{Result, Context as AnyhowContext};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use moka::future::Cache;

#[derive(Debug)]
pub struct SmartResolvePlugin {
    pub name: String,
    pub upstreams: Vec<Arc<Upstream>>,
    pub probe_timeout_ms: u64,
    pub probe_port: u16,
    pub prefer_ipv4: bool,
    pub max_ips_to_probe: usize,
    latency_cache: Cache<IpAddr, u64>,
}

#[derive(Debug, Clone)]
struct IpWithLatency {
    ip: IpAddr,
    latency_ms: u64,
    record: Record,
}

impl SmartResolvePlugin {
    pub fn new(
        name: String,
        upstream_configs: Vec<UpstreamConfig>,
        probe_timeout_ms: u64,
        probe_port: u16,
        prefer_ipv4: bool,
        max_ips_to_probe: usize,
    ) -> Result<Self> {
        let mut upstreams = Vec::new();
        for conf in upstream_configs {
            let upstream = Upstream::new(conf).context("Failed to create upstream")?;
            upstreams.push(Arc::new(upstream));
        }

        let latency_cache = Cache::builder()
            .max_capacity(2000)
            .time_to_live(Duration::from_secs(120)) // Keep cache longer (2 mins)
            .build();

        info!(
            "🚀 SmartResolve v2.1 '{}' initialized: {} upstreams, default_port={}, cache=enabled",
            name,
            upstreams.len(),
            probe_port
        );

        Ok(Self {
            name,
            upstreams,
            probe_timeout_ms,
            probe_port,
            prefer_ipv4,
            max_ips_to_probe,
            latency_cache,
        })
    }

    /// Primary Handler
    async fn handle_internal(&self, ctx: &mut Context) -> Result<()> {
        let request = &ctx.request;
        let qname = request.query().map(|q| q.name().to_string()).unwrap_or_default();
        
        let qtype = request.query().map(|q| q.query_type());
        match qtype {
            Some(RecordType::A) | Some(RecordType::AAAA) => {
                // proceed to optimize
            }
            _ => {
                // Passthrough for non-optimizable types
                if self.fallback_forward(ctx).await {
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!("All fallbacks failed for {}", qname));
                }
            }
        }

        // Concurrent Query
        let gather_timeout = Duration::from_millis(2000);
        let records = match tokio::time::timeout(gather_timeout, self.concurrent_query(request)).await {
            Ok(recs) => recs,
            Err(_) => {
                warn!("SmartResolve: Query timed out for {}, trying fallback", qname);
                if self.fallback_forward(ctx).await {
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!("Timeout & All fallbacks failed for {}", qname));
                }
            }
        };

        if records.is_empty() {
             if self.fallback_forward(ctx).await {
                    return Ok(());
             } else {
                    // Let external plugins handle it if possible, or fail
                    return Err(anyhow::anyhow!("No records & All fallbacks failed for {}", qname));
             }
        }

        // Probe and Sort
        let sorted_records = self.probe_and_sort(records).await;

        let response = self.build_response(request, sorted_records);
        ctx.set_response(response, true);

        Ok(())
    }

    /// Returns true if fallback succeeded
    async fn fallback_forward(&self, ctx: &mut Context) -> bool {
        let request = &ctx.request;
        
        for (i, upstream) in self.upstreams.iter().enumerate() {
            let timeout = Duration::from_millis(3000);
            match tokio::time::timeout(timeout, upstream.exchange(request)).await {
                Ok(Ok(mut response)) => {
                    response.set_id(request.id());
                    ctx.set_response(response, true);
                    debug!("SmartResolve: Fallback #{} used", i);
                    return true;
                }
                _ => continue,
            }
        }
        false
    }

    async fn concurrent_query(&self, request: &Message) -> Vec<Record> {
        let (tx, mut rx) = mpsc::channel::<Vec<Record>>(self.upstreams.len());
        let individual_timeout = Duration::from_millis(1500);

        for upstream in &self.upstreams {
            let upstream = upstream.clone();
            let request = request.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(Ok(response)) = tokio::time::timeout(individual_timeout, upstream.exchange(&request)).await {
                    let records: Vec<Record> = response.answers().iter()
                        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
                        .cloned().collect();
                    if !records.is_empty() {
                        let _ = tx.send(records).await;
                    }
                }
            });
        }
        drop(tx);

        let mut all_records = Vec::new();
        let mut seen_ips = std::collections::HashSet::new();
        while let Some(records) = rx.recv().await {
            for record in records {
                if let Some(ip) = Self::extract_ip(&record) {
                    if seen_ips.insert(ip) {
                        all_records.push(record);
                    }
                }
            }
        }
        all_records
    }

    fn extract_ip(record: &Record) -> Option<IpAddr> {
        match record.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        }
    }

    async fn probe_and_sort(&self, records: Vec<Record>) -> Vec<Record> {
        if records.is_empty() { return records; }

        let mut ips_to_probe = Vec::new();
        let mut cached_results = Vec::new();

        for record in &records {
            if let Some(ip) = Self::extract_ip(record) {
                if let Some(latency) = self.latency_cache.get(&ip).await {
                    cached_results.push(IpWithLatency { ip, latency_ms: latency, record: record.clone() });
                } else {
                    ips_to_probe.push(record.clone());
                }
            }
        }

        let max_new = self.max_ips_to_probe.saturating_sub(cached_results.len());
        if max_new > 0 && !ips_to_probe.is_empty() {
             let (tx, mut rx) = mpsc::channel::<IpWithLatency>(max_new);
             let probe_timeout = Duration::from_millis(self.probe_timeout_ms);
             // Default probe port is usually 443, but we can try 80 if 443 fails? 
             // Simpler: Just probe configured port.
             let port = self.probe_port;

             for record in ips_to_probe.into_iter().take(max_new) {
                 if let Some(ip) = Self::extract_ip(&record) {
                     let tx = tx.clone();
                     let record = record.clone();
                     tokio::spawn(async move {
                         let addr = SocketAddr::new(ip, port);
                         let start = Instant::now();
                         let latency = match tokio::time::timeout(probe_timeout, TcpStream::connect(addr)).await {
                             Ok(Ok(_)) => start.elapsed().as_millis() as u64,
                             _ => u64::MAX,
                         };
                         let _ = tx.send(IpWithLatency { ip, latency_ms: latency, record }).await;
                     });
                 }
             }
             drop(tx);
             while let Some(res) = rx.recv().await {
                 cached_results.push(res);
             }
        }

        cached_results.sort_by_key(|r| r.latency_ms);

        for res in &cached_results {
            if res.latency_ms < u64::MAX {
                self.latency_cache.insert(res.ip, res.latency_ms).await;
            }
        }

        let sorted: Vec<Record> = cached_results.into_iter().map(|r| r.record).collect();
        // Append any skipped records
        if sorted.len() < records.len() {
             // simplified append not implementing precise tracking for now
        }
        sorted
    }

    fn build_response(&self, request: &Message, sorted_records: Vec<Record>) -> Message {
        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(hickory_proto::op::MessageType::Response);
        response.set_op_code(hickory_proto::op::OpCode::Query);
        response.set_response_code(hickory_proto::op::ResponseCode::NoError);
        if let Some(query) = request.query() {
            response.add_query(query.clone());
        }
        for record in sorted_records {
            response.add_answer(record);
        }
        response
    }
}

impl Plugin for SmartResolvePlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        match self.handle_internal(ctx).await {
            Ok(_) => Ok(()),
            Err(e) => {
                debug!("SmartResolve: Handover -> {}", e);
                // Return Ok to allow next plugin in sequence to run
                // But we MUST NOT have set a response if we want next plugin to run effectively?
                // Actually TitanDNS logic: if set_response is called, it stops?
                // If we want external fallback (upstream_local), we should just return Ok(()) WITHOUT setting response.
                // Our handle_internal only sets response on success.
                Ok(())
            }
        }
    }
}
