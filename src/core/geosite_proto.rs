// This file is manually defined for MVP to avoid prost-build complexity.
// It corresponds to the V2Ray Geosite protobuf definition.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<GeoSiteEntry>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSiteEntry {
    #[prost(string, tag="1")]
    pub country_code: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub domain: ::prost::alloc::vec::Vec<Domain>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    #[prost(enumeration="domain::Type", tag="1")]
    pub r#type: i32,
    #[prost(string, tag="2")]
    pub value: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="3")]
    pub attribute: ::prost::alloc::vec::Vec<DomainAttribute>,
}

/// Nested message and enum types in `Domain`.
pub mod domain {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Plain = 0,
        Regex = 1,
        RootDomain = 2,
        Full = 3,
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainAttribute {
    #[prost(string, tag="1")]
    pub key: ::prost::alloc::string::String,
    #[prost(oneof="domain_attribute::TypedValue", tags="2, 3, 4")]
    pub typed_value: ::core::option::Option<domain_attribute::TypedValue>,
}

/// Nested message and enum types in `DomainAttribute`.
pub mod domain_attribute {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag="2")]
        BoolValue(bool),
        #[prost(int64, tag="3")]
        IntValue(i64),
    }
}
