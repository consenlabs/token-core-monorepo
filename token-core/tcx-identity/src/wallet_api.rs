#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenerateMnemonicResult {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateIdentityParam {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "3")]
    pub password_hint: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, tag = "4")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub seg_wit: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateIdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub wallets: ::prost::alloc::vec::Vec<Wallet>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Wallet {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub address: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub created_at: u64,
    #[prost(string, tag = "4")]
    pub source: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "6")]
    pub external_address: ::core::option::Option<ExternalAddress>,
    #[prost(string, optional, tag = "7")]
    pub enc_x_pub: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "8")]
    pub seg_wit: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalAddress {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub derived_path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetCurrentIdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub wallets: ::prost::alloc::vec::Vec<ImtKeystore>,
    #[prost(message, optional, tag = "4")]
    pub metadata: ::core::option::Option<Metadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metadata {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "2")]
    pub password_hint: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, tag = "3")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub timestamp: u64,
    #[prost(string, tag = "5")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "6")]
    pub backup: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "7")]
    pub source: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "8")]
    pub mode: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "9")]
    pub wallet_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "10")]
    pub seg_wit: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImtKeystore {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub version: u32,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "4")]
    pub mnemonic_path: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "5")]
    pub metadata: ::core::option::Option<Metadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportIdentityParam {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportIdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub mnemonic: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoverIdentityParam {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub mnemonic: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "4")]
    pub password_hint: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub seg_wit: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoverIdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub mnemonic: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub wallets: ::prost::alloc::vec::Vec<Wallet>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveIdentityParam {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveIdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct V3KeystoreImportInput {
    #[prost(string, tag = "1")]
    pub keystore: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(bool, tag = "3")]
    pub overwrite: bool,
    #[prost(string, tag = "4")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub source: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct V3KeystoreExportInput {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct V3KeystoreExportOutput {
    #[prost(string, tag = "1")]
    pub json: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptDataToIpfsParam {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub content: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptDataToIpfsResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub encrypted: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptDataFromIpfsParam {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub encrypted: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptDataFromIpfsResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub content: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignAuthenticationMessageParam {
    #[prost(uint64, tag = "1")]
    pub access_time: u64,
    #[prost(string, tag = "2")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub device_token: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignAuthenticationMessageResult {
    #[prost(uint64, tag = "1")]
    pub access_time: u64,
    #[prost(string, tag = "2")]
    pub signature: ::prost::alloc::string::String,
}
