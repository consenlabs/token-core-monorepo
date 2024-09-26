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
