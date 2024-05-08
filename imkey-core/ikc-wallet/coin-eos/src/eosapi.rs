#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosTxInput {
    #[prost(message, repeated, tag = "1")]
    pub transactions: ::prost::alloc::vec::Vec<EosSignData>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosSignData {
    #[prost(string, tag = "1")]
    pub tx_hex: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "2")]
    pub public_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "3")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub receiver: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub payment: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub sender: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosTxOutput {
    #[prost(message, repeated, tag = "1")]
    pub trans_multi_signs: ::prost::alloc::vec::Vec<EosSignResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosSignResult {
    #[prost(string, tag = "1")]
    pub hash: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "2")]
    pub signs: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosMessageInput {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub pubkey: ::prost::alloc::string::String,
    #[prost(bool, tag = "3")]
    pub is_hex: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
