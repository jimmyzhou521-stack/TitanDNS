use anyhow::Result;
use hickory_proto::op::{Message, MessageType, ResponseCode, OpCode};
use hickory_proto::rr::{Record, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::debug;

use crate::core::context::Context;
use crate::core::plugin::Plugin;

/// Reject/Blackhole Plugin
/// 
/// Returns NXDOMAIN or a blackhole IP (0.0.0.0 / ::) for matched queries.
/// Used for ad-blocking, malware filtering, or parental controls.
#[derive(Debug, Clone)]
pub struct RejectPlugin {
    pub name: String,
    pub rcode: RejectType,
}

#[derive(Debug, Clone)]
pub enum RejectType {
    /// Return NXDOMAIN
    NxDomain,
    /// Return REFUSED
    Refused,
    /// Return SERVFAIL
    ServFail,
    /// Return empty response (NOERROR with 0 answers)
    NoError,
    /// Return blackhole IPv4 (0.0.0.0)
    BlackholeV4,
    /// Return blackhole IPv6 (::)
    BlackholeV6,
    /// Return custom IP
    CustomIp(String),
}

impl Plugin for RejectPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let query = match ctx.request.query() {
            Some(q) => q,
            None => return Ok(()),
        };

        let qname = query.name().clone();
        let qtype = query.query_type();

        debug!("🚫 Rejecting query for: {} (type: {:?})", qname, self.rcode);

        let mut response = Message::new();
        response.set_id(ctx.request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_authoritative(false);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);
        response.add_query(query.clone());

        match &self.rcode {
            RejectType::NxDomain => {
                response.set_response_code(ResponseCode::NXDomain);
            }
            RejectType::Refused => {
                response.set_response_code(ResponseCode::Refused);
            }
            RejectType::ServFail => {
                response.set_response_code(ResponseCode::ServFail);
            }
            RejectType::NoError => {
                response.set_response_code(ResponseCode::NoError);
                // No answers added, just empty response
            }
            RejectType::BlackholeV4 => {
                response.set_response_code(ResponseCode::NoError);
                if qtype == RecordType::A {
                    let rdata = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(0, 0, 0, 0)));
                    let record = Record::from_rdata(qname, 300, rdata);
                    response.add_answer(record);
                }
            }
            RejectType::BlackholeV6 => {
                response.set_response_code(ResponseCode::NoError);
                if qtype == RecordType::AAAA {
                    let rdata = RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
                    let record = Record::from_rdata(qname, 300, rdata);
                    response.add_answer(record);
                }
            }
            RejectType::CustomIp(ip_str) => {
                response.set_response_code(ResponseCode::NoError);
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    match ip {
                        std::net::IpAddr::V4(v4) if qtype == RecordType::A => {
                            let rdata = RData::A(hickory_proto::rr::rdata::A(v4));
                            let record = Record::from_rdata(qname, 300, rdata);
                            response.add_answer(record);
                        }
                        std::net::IpAddr::V6(v6) if qtype == RecordType::AAAA => {
                            let rdata = RData::AAAA(hickory_proto::rr::rdata::AAAA(v6));
                            let record = Record::from_rdata(qname, 300, rdata);
                            response.add_answer(record);
                        }
                        _ => {}
                    }
                }
            }
        }

        ctx.set_response(response, true);
        Ok(())
    }
}

impl RejectPlugin {
    pub fn new(name: String, rcode: RejectType) -> Self {
        Self { name, rcode }
    }
}
