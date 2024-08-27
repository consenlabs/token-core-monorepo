/// Action Wrapper
/// There is a `call_imkey_api` method in tcx which act as a endpoint like RPC. It accepts a `ImkeyAction` param which method field is
/// the real action and param field is the real param of that method.
/// When an error occurred, the `call_imkey_api` will return a `Response` which isSuccess field be false and error field is the reason
/// which cause the error.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImkeyAction {
    #[prost(string, tag = "1")]
    pub method: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub param: ::core::option::Option<::prost_types::Any>,
}
/// A common response when error occurred.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorResponse {
    #[prost(bool, tag = "1")]
    pub is_success: bool,
    #[prost(string, tag = "2")]
    pub error: ::prost::alloc::string::String,
}
/// A commonresponse when successfully ended.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommonResponse {
    #[prost(string, tag = "1")]
    pub result: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressParam {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub seg_wit: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressResult {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubKeyParam {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubKeyResult {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub pub_key: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub derived_mode: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalAddress {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub derived_path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub r#type: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinWallet {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub enc_x_pub: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub external_address: ::core::option::Option<ExternalAddress>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosWallet {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub address: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub public_keys: ::prost::alloc::vec::Vec<eos_wallet::PubKeyInfo>,
}
/// Nested message and enum types in `EosWallet`.
pub mod eos_wallet {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PubKeyInfo {
        #[prost(string, tag = "1")]
        pub path: ::prost::alloc::string::String,
        #[prost(string, tag = "2")]
        pub derived_mode: ::prost::alloc::string::String,
        #[prost(string, tag = "3")]
        pub public_key: ::prost::alloc::string::String,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalAddressParam {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub seg_wit: ::prost::alloc::string::String,
    #[prost(int32, tag = "5")]
    pub external_idx: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitImKeyCoreXParam {
    #[prost(string, tag = "1")]
    pub file_dir: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub xpub_common_key: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub xpub_common_iv: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub is_debug: bool,
    #[prost(string, tag = "5")]
    pub system: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcForkWallet {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub enc_x_pub: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveAccountsParam {
    #[prost(message, repeated, tag = "1")]
    pub derivations: ::prost::alloc::vec::Vec<derive_accounts_param::Derivation>,
}
/// Nested message and enum types in `DeriveAccountsParam`.
pub mod derive_accounts_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Derivation {
        #[prost(string, tag = "1")]
        pub chain_type: ::prost::alloc::string::String,
        #[prost(string, tag = "2")]
        pub path: ::prost::alloc::string::String,
        #[prost(string, tag = "3")]
        pub network: ::prost::alloc::string::String,
        #[prost(string, tag = "4")]
        pub seg_wit: ::prost::alloc::string::String,
        #[prost(string, tag = "5")]
        pub chain_id: ::prost::alloc::string::String,
        #[prost(string, tag = "6")]
        pub curve: ::prost::alloc::string::String,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountResponse {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub public_key: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub extended_public_key: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub encrypted_extended_public_key: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub seg_wit: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveAccountsResult {
    #[prost(message, repeated, tag = "1")]
    pub accounts: ::prost::alloc::vec::Vec<AccountResponse>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveSubAccountsParam {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub seg_wit: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "5")]
    pub relative_paths: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "6")]
    pub extended_public_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveSubAccountsResult {
    #[prost(message, repeated, tag = "1")]
    pub accounts: ::prost::alloc::vec::Vec<AccountResponse>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetExtendedPublicKeysParam {
    #[prost(message, repeated, tag = "1")]
    pub derivations: ::prost::alloc::vec::Vec<PublicKeyDerivation>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetExtendedPublicKeysResult {
    #[prost(string, repeated, tag = "1")]
    pub extended_public_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyDerivation {
    #[prost(string, tag = "1")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub curve: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysParam {
    #[prost(message, repeated, tag = "1")]
    pub derivations: ::prost::alloc::vec::Vec<PublicKeyDerivation>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysResult {
    #[prost(string, repeated, tag = "1")]
    pub public_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitImKeyServerParam {
    #[prost(string, tag = "1")]
    pub url: ::prost::alloc::string::String,
}
