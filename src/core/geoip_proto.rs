// This file is manually defined for MVP to avoid prost-build complexity.
// It corresponds to the V2Ray GeoIP protobuf definition.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<GeoIpEntry>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIpEntry {
    #[prost(string, tag="1")]
    pub country_code: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub cidr: ::prost::alloc::vec::Vec<Cidr>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cidr {
    #[prost(bytes="vec", tag="1")]
    pub ip: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub prefix: u32,
}
