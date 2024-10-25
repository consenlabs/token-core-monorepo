#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxInput {
    #[prost(string, tag = "2")]
    pub raw_data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageInput {
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
    #[prost(bool, tag = "2")]
    pub is_hex: bool,
    #[prost(string, tag = "3")]
    pub header: ::prost::alloc::string::String,
    #[prost(uint32, tag = "4")]
    pub version: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
