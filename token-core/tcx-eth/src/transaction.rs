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
    pub tx_type: ::prost::alloc::string::String,
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
    #[prost(bool, optional, tag = "2")]
    pub is_hex: ::core::option::Option<bool>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthRecoverAddressInput {
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub signature: ::prost::alloc::string::String,
    #[prost(bool, optional, tag = "3")]
    pub is_hex: ::core::option::Option<bool>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthRecoverAddressOutput {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
}
