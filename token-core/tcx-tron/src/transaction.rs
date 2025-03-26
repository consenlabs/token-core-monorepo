/// FUNCTION: sign_tx(SignParam{input: TronTxInput}): TronTxOutput
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxInput {
    /// hex string
    #[prost(string, tag = "1")]
    pub raw_data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxOutput {
    /// hex string
    #[prost(string, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// FUNCTION: tron_sign_message(SignParam): TronMessageOutput
///
/// This api use the a common struct named `SignParam`, you should
/// build the `TronMessageInput` and put it in the `input` field
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageInput {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
    /// "TRON","ETH","NONE"
    #[prost(string, tag = "2")]
    pub header: ::prost::alloc::string::String,
    /// 1: V1 2:V2 3:TIP-712
    #[prost(uint32, tag = "3")]
    pub version: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
