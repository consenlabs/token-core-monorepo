/// FUNCTION: sign_tx(SignParam{input: BtcKinTxInput}): BtcKinTxOutput
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Utxo {
    #[prost(string, tag = "1")]
    pub tx_hash: ::prost::alloc::string::String,
    #[prost(int32, tag = "2")]
    pub vout: i32,
    #[prost(int64, tag = "3")]
    pub amount: i64,
    #[prost(string, tag = "4")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub derived_path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcKinTxInput {
    #[prost(message, repeated, tag = "1")]
    pub inputs: ::prost::alloc::vec::Vec<Utxo>,
    #[prost(string, tag = "2")]
    pub to: ::prost::alloc::string::String,
    #[prost(int64, tag = "3")]
    pub amount: i64,
    #[prost(int64, tag = "4")]
    pub fee: i64,
    #[prost(string, optional, tag = "5")]
    pub op_return: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag = "6")]
    pub change_address_index: ::core::option::Option<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcKinTxOutput {
    #[prost(string, tag = "1")]
    pub raw_tx: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub tx_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub wtx_hash: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OmniTxInput {
    #[prost(message, repeated, tag = "1")]
    pub inputs: ::prost::alloc::vec::Vec<Utxo>,
    #[prost(string, tag = "2")]
    pub to: ::prost::alloc::string::String,
    #[prost(int64, tag = "3")]
    pub amount: i64,
    #[prost(int64, tag = "4")]
    pub fee: i64,
    #[prost(int32, tag = "5")]
    pub property_id: i32,
}
