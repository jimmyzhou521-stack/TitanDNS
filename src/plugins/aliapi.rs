
use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use tracing::{debug, info};

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// Aliyun HTTPDNS Plugin
/// 
/// Uses Alibaba Cloud's HTTPDNS API (DoH JSON) to resolve domains via HTTP.
/// This bypasses standard DNS pollution and provides high-speed lookup.
/// 
/// Implementation based on MosDNS aliapi plugin.
/// Docs: https://help.aliyun.com/document_detail/432223.html
#[derive(Debug)]
pub struct AliApiPlugin {
    pub name: String,
    pub account_id: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub server_addr: String,
    pub client: Client,
    pub timeout: std::time::Duration,
}

/// AliDNS JSON API Response Format
/// Matches the format from http://223.5.5.5/resolve endpoint
/// IMPORTANT: AliDNS returns UPPERCASE field names!
#[derive(Debug, Deserialize)]
struct AliDNSResponse {
    #[serde(rename = "Status")]
    status: i32,           // DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)
    #[serde(rename = "TC")]
    tc: bool,              // Truncated
    #[serde(rename = "RD")]
    rd: bool,              // Recursion Desired
    #[serde(rename = "RA")]
    ra: bool,              // Recursion Available
    #[serde(rename = "AD")]
    ad: bool,              // Authenticated Data
    #[serde(rename = "CD")]
    cd: bool,              // Checking Disabled
    #[serde(rename = "Answer")]
    answer: Vec<AliDNSAnswer>,
    #[serde(rename = "Question", default)]
    question: Option<AliDNSQuestion>,
}

#[derive(Debug, Deserialize)]
struct AliDNSQuestion {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "type")]
    qtype: u16,
}

#[derive(Debug, Deserialize)]
struct AliDNSAnswer {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "data")]
    data: String,
}

impl Plugin for AliApiPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let qname = ctx.qname_ref();
        // Ensure FQDN format with trailing dot for API
        let domain = if qname.ends_with('.') {
            qname.to_string()
        } else {
            format!("{}.", qname)
        };
        
        // Get query type
        let query = ctx.request.query().ok_or(anyhow::anyhow!("No query"))?;
        let qtype = match query.query_type() {
            hickory_proto::rr::RecordType::A => "A",
            hickory_proto::rr::RecordType::AAAA => "AAAA",
            hickory_proto::rr::RecordType::CNAME => "CNAME",
            hickory_proto::rr::RecordType::MX => "MX",
            hickory_proto::rr::RecordType::TXT => "TXT",
            hickory_proto::rr::RecordType::NS => "NS",
            _ => "A",
        };

        // Extract EDNS0 Client Subnet (ECS) from request
        // This enables location-based DNS resolution via AliDNS
        let edns_client_subnet = self.extract_edns_client_subnet(ctx);

        // Generate timestamp (Unix timestamp in seconds)
        let ts = chrono::Utc::now().timestamp();
        
        // Generate SHA256 signature (MosDNS format)
        // key = SHA256(AccountID + AccessKeySecret + timestamp + qname + AccessKeyID)
        let key_data = format!("{}{}{}{}{}", 
            self.account_id, 
            self.access_key_secret, 
            ts, 
            domain, 
            self.access_key_id
        );
        let mut hasher = Sha256::new();
        hasher.update(key_data.as_bytes());
        let key_hash = hasher.finalize();
        let key_str = hex::encode(key_hash);

        // Build URL
        // Format: http://{server}/resolve?name={domain}&type={qtype}&uid={account_id}&ak={access_key_id}&key={signature}&ts={timestamp}[&edns_client_subnet={ip}/{mask}]
        let mut url = format!(
            "http://{}/resolve?name={}&type={}&uid={}&ak={}&key={}&ts={}",
            self.server_addr, domain, qtype, self.account_id, self.access_key_id, key_str, ts
        );

        // Append EDNS0 Client Subnet if present
        if let Some(subnet) = &edns_client_subnet {
            url = format!("{}&edns_client_subnet={}", url, subnet);
            info!("🌍 AliAPI with ECS: {}", subnet);
        }

        info!("🌐 AliAPI Request: {}", url);

        // Execute Request
        let resp = self.client.get(&url)
            .timeout(self.timeout)
            .send().await?;
        
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            debug!("❌ AliAPI Error: HTTP {} - {}", status, body);
            return Err(anyhow::anyhow!("AliAPI returned HTTP {}: {}", status, body));
        }

        let resp_json: AliDNSResponse = resp.json().await?;
        debug!("📥 AliAPI Response: {:?}", resp_json);
        info!("📥 AliAPI: {} answers for {} (status: {})",
              resp_json.answer.len(), qname, resp_json.status);

        // Build DNS Response
        use hickory_proto::rr::{RData, Record};
        use hickory_proto::op::ResponseCode;
        use std::str::FromStr;

        let name = query.name().clone();

        let mut response = hickory_proto::op::Message::new();
        response.set_id(ctx.request.id());
        response.set_message_type(hickory_proto::op::MessageType::Response);
        response.set_op_code(hickory_proto::op::OpCode::Query);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);
        response.add_query(query.clone());

        // Map AliDNS status code to DNS response code
        // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, etc.
        let rcode = match resp_json.status {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            _ => ResponseCode::from(0, resp_json.status as u8),
        };
        response.set_response_code(rcode);

        // Set DNS flags from AliDNS response
        response.set_truncated(resp_json.tc);
        response.set_authoritative(resp_json.ad);
        response.set_checking_disabled(resp_json.cd);

        // Only add answers if status is NOERROR (0)
        if resp_json.status == 0 {
            for ans in resp_json.answer {
                match ans.record_type {
                    1 => { // A record
                        if let Ok(ip) = ans.data.parse::<std::net::Ipv4Addr>() {
                            let rdata = RData::A(hickory_proto::rr::rdata::A(ip));
                            let record = Record::from_rdata(name.clone(), ans.ttl, rdata);
                            response.add_answer(record);
                        }
                    },
                    28 => { // AAAA record
                        if let Ok(ip) = ans.data.parse::<std::net::Ipv6Addr>() {
                            let rdata = RData::AAAA(hickory_proto::rr::rdata::AAAA(ip));
                            let record = Record::from_rdata(name.clone(), ans.ttl, rdata);
                            response.add_answer(record);
                        }
                    },
                    5 => { // CNAME record
                        if let Ok(cname) = hickory_proto::rr::Name::from_str(&ans.data) {
                            let rdata = RData::CNAME(hickory_proto::rr::rdata::CNAME(cname));
                            let record = Record::from_rdata(name.clone(), ans.ttl, rdata);
                            response.add_answer(record);
                        }
                    },
                    _ => {
                        // Unsupported record type, log and skip
                        debug!("⚠️ AliAPI: Unsupported record type {} for {}", ans.record_type, ans.name);
                    }
                }
            }
        }

        // Always set response, even for NXDOMAIN/SERVFAIL
        info!("✅ AliAPI: {} answers for {} (rcode: {:?})", response.answer_count(), qname, rcode);
        ctx.set_response(response, true);

        Ok(())
    }
}

impl AliApiPlugin {
    pub fn new(
        account_id: String,
        access_key_id: String,
        access_key_secret: String,
        timeout_ms: Option<u64>,
    ) -> Self {
        let timeout = timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(5));
        Self {
            name: "aliapi".to_string(),
            account_id,
            access_key_id,
            access_key_secret,
            server_addr: "223.5.5.5".to_string(), // Default to public AliDNS
            client: Client::new(),
            timeout,
        }
    }
    
    pub fn with_server(mut self, server: String) -> Self {
        if !server.is_empty() {
            self.server_addr = server;
        }
        self
    }

    /// Extract client IP for EDNS0 Client Subnet (ECS)
    /// Returns Option<String> in format "IP/PREFIX" (e.g., "192.168.1.1/24")
    /// This enables AliDNS to return location-based results
    ///
    /// Note: This implementation uses the actual client IP address rather than
    /// extracting from EDNS0, which provides the same practical benefit for
    /// geo-based DNS resolution.
    fn extract_edns_client_subnet(&self, ctx: &Context) -> Option<String> {
        let client_ip = ctx.client_addr.ip();

        // Skip loopback and unspecified addresses
        if client_ip.is_loopback() || client_ip.is_unspecified() {
            debug!("🌍 Client IP is loopback/unspecified, skipping ECS");
            return None;
        }

        // Apply appropriate subnet mask based on IP version
        let subnet = match client_ip {
            std::net::IpAddr::V4(_) => format!("{}/24", client_ip),
            std::net::IpAddr::V6(_) => format!("{}/56", client_ip),
        };

        info!("🌍 AliAPI ECS: {}", subnet);
        Some(subnet)
    }
}
