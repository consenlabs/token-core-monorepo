#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTxInput {
    #[prost(string, tag = "1")]
    pub nonce: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub gas_price: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub gas_limit: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub to: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub value: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub data: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub max_fee_per_gas: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub max_priority_fee_per_gas: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "11")]
    pub access_list: ::prost::alloc::vec::Vec<AccessList>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessList {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "2")]
    pub storage_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTxOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub tx_hash: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthMessageInput {
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
    #[prost(bool, tag = "2")]
    pub is_personal_sign: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignTxsInput {
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<SignTxsItem>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignTxsItem {
    #[prost(message, optional, tag = "1")]
    pub tx: ::core::option::Option<EthTxInput>,
    #[prost(string, tag = "2")]
    pub payment: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub receiver: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub fee: ::prost::alloc::string::String,
    /// Per-item HD path override. Empty string falls back to
    /// `SignParam.path` (the outer batch-shared default).
    #[prost(string, tag = "6")]
    pub path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignTxsOutput {
    #[prost(message, repeated, tag = "1")]
    pub outputs: ::prost::alloc::vec::Vec<EthTxOutput>,
}
