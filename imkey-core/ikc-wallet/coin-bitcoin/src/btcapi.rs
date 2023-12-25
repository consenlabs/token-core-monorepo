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
    pub script_pub_key: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub derived_path: ::prost::alloc::string::String,
    #[prost(int64, tag = "7")]
    pub sequence: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTxExtra {
    #[prost(string, tag = "1")]
    pub op_return: ::prost::alloc::string::String,
    #[prost(int32, tag = "2")]
    pub property_id: i32,
    #[prost(string, tag = "3")]
    pub fee_mode: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTxInput {
    #[prost(string, tag = "1")]
    pub to: ::prost::alloc::string::String,
    #[prost(int64, tag = "2")]
    pub amount: i64,
    #[prost(int64, tag = "3")]
    pub fee: i64,
    #[prost(uint32, tag = "4")]
    pub change_address_index: u32,
    #[prost(message, repeated, tag = "5")]
    pub unspents: ::prost::alloc::vec::Vec<Utxo>,
    #[prost(string, tag = "6")]
    pub seg_wit: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub protocol: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "8")]
    pub extra: ::core::option::Option<BtcTxExtra>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTxOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub tx_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub wtx_hash: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcXpubReq {
    #[prost(string, tag = "1")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcXpubRes {
    #[prost(string, tag = "1")]
    pub xpub: ::prost::alloc::string::String,
}
