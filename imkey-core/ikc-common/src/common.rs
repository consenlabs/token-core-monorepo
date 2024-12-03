#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignParam {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub input: ::core::option::Option<::prost_types::Any>,
    #[prost(string, tag = "5")]
    pub payment: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub receiver: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub fee: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub seg_wit: ::prost::alloc::string::String,
}
