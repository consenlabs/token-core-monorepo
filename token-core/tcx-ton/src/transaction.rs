#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TonRawTxIn {
    #[prost(string, tag = "1")]
    pub raw_data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TonTxOut {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TonTxIn {
    #[prost(string, tag = "1")]
    pub from: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub to: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub amount: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub memo: ::prost::alloc::string::String,
    #[prost(bool, tag = "5")]
    pub is_jetton: bool,
    #[prost(string, tag = "6")]
    pub jetton_amount: ::prost::alloc::string::String,
    #[prost(uint64, tag = "7")]
    pub query_id: u64,
    #[prost(int32, tag = "8")]
    pub sequence_no: i32,
    #[prost(string, tag = "9")]
    pub wallet_version: ::prost::alloc::string::String,
}
