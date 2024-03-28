#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosAccount {
    #[prost(string, tag = "1")]
    pub account_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosTxInput {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "2")]
    pub tx_hexs: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigData {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub hash: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosTxOutput {
    #[prost(message, repeated, tag = "1")]
    pub sig_data: ::prost::alloc::vec::Vec<SigData>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosMessageInput {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
