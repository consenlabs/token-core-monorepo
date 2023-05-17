#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenerateMnemonicResult {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
}
