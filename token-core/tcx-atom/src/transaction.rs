/// FUNCTION: sign_tx(SignParam{input: AtomTxInput}): AtomTxOutput
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AtomTxInput {
    /// hex string
    #[prost(string, tag = "1")]
    pub raw_data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AtomTxOutput {
    /// hex string
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
