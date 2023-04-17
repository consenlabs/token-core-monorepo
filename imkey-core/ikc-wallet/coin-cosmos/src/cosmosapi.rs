#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosmosTxInput {
    #[prost(string, tag = "1")]
    pub data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosmosTxOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
