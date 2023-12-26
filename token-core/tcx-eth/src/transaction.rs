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
    #[prost(enumeration = "SignatureType", tag = "2")]
    pub signature_type: i32,
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
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthRecoverAddressOutput {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SignatureType {
    PersonalSign = 0,
    EcSign = 1,
}
impl SignatureType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            SignatureType::PersonalSign => "PersonalSign",
            SignatureType::EcSign => "EcSign",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PersonalSign" => Some(Self::PersonalSign),
            "EcSign" => Some(Self::EcSign),
            _ => None,
        }
    }
}
