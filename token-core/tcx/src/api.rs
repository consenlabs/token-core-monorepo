/// Action Wrapper
/// There is a `call_tcx_api` method in tcx which act as a endpoint like RPC. It accepts a `TcxAction` param which method field is
/// the real action and param field is the real param of that method.
/// When an error occurred, the `call_tcx_api` will return a `Response` which isSuccess field be false and error field is the reason
/// which cause the error.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TcxAction {
    #[prost(string, tag = "1")]
    pub method: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub param: ::core::option::Option<::prost_types::Any>,
}
/// A common response when error occurred.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeneralResult {
    #[prost(bool, tag = "1")]
    pub is_success: bool,
    #[prost(string, tag = "2")]
    pub error: ::prost::alloc::string::String,
}
/// FUNCTION: init_token_core_x(InitTokenCoreXParam)
///
/// initialize tcx by passing keystore folder and xpub encryption params
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitTokenCoreXParam {
    #[prost(string, tag = "1")]
    pub file_dir: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub xpub_common_key: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub xpub_common_iv: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub is_debug: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignHashesParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub data_to_sign: ::prost::alloc::vec::Vec<sign_hashes_param::DataToSign>,
    #[prost(oneof = "sign_hashes_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<sign_hashes_param::Key>,
}
/// Nested message and enum types in `SignHashesParam`.
pub mod sign_hashes_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DataToSign {
        #[prost(string, tag = "1")]
        pub hash: ::prost::alloc::string::String,
        #[prost(string, tag = "2")]
        pub path: ::prost::alloc::string::String,
        #[prost(string, tag = "3")]
        pub curve: ::prost::alloc::string::String,
        #[prost(string, tag = "4")]
        pub sig_alg: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignHashesResult {
    #[prost(string, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
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
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub derivations: ::prost::alloc::vec::Vec<PublicKeyDerivation>,
    #[prost(oneof = "get_public_keys_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<get_public_keys_param::Key>,
}
/// Nested message and enum types in `GetPublicKeysParam`.
pub mod get_public_keys_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysResult {
    #[prost(string, repeated, tag = "1")]
    pub public_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetExtendedPublicKeysParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub derivations: ::prost::alloc::vec::Vec<PublicKeyDerivation>,
    #[prost(oneof = "get_extended_public_keys_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<get_extended_public_keys_param::Key>,
}
/// Nested message and enum types in `GetExtendedPublicKeysParam`.
pub mod get_extended_public_keys_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetExtendedPublicKeysResult {
    #[prost(string, repeated, tag = "1")]
    pub extended_public_keys: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
///
/// // FUNCTION: export_private_key(ExportPrivateKeyParam): ExportResult
/// //
/// // export the private key from a private key keystore or a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportPrivateKeyParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub path: ::prost::alloc::string::String,
    #[prost(oneof = "export_private_key_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<export_private_key_param::Key>,
}
/// Nested message and enum types in `ExportPrivateKeyParam`.
pub mod export_private_key_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
///
/// // FUNCTION: export_private_key(ExportPrivateKeyParam): ExportResult
/// //
/// // export the private key from a private key keystore or a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportJsonParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub path: ::prost::alloc::string::String,
}
///
/// /// Keystore Common
///
/// // FUNCTION: verify_password(WalletKeyParam) -> Response
/// //
/// // verify the password of the keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WalletKeyParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(oneof = "wallet_key_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<wallet_key_param::Key>,
}
/// Nested message and enum types in `WalletKeyParam`.
pub mod wallet_key_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportMnemonicParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(oneof = "export_mnemonic_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<export_mnemonic_param::Key>,
}
/// Nested message and enum types in `ExportMnemonicParam`.
pub mod export_mnemonic_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthBatchPersonalSignParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "4")]
    pub data: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub path: ::prost::alloc::string::String,
    #[prost(oneof = "eth_batch_personal_sign_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<eth_batch_personal_sign_param::Key>,
}
/// Nested message and enum types in `EthBatchPersonalSignParam`.
pub mod eth_batch_personal_sign_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthBatchPersonalSignResult {
    #[prost(string, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// FUNCTION: create_keystore(CreateKeystoreParam): KeystoreResult
///
/// create a new hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateKeystoreParam {
    #[prost(string, tag = "1")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password_hint: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub network: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdentityResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub ipfs_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeystoreResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub source: ::prost::alloc::string::String,
    #[prost(int64, tag = "6")]
    pub created_at: i64,
    #[prost(string, tag = "7")]
    pub source_fingerprint: ::prost::alloc::string::String,
}
/// FUNCTION: import_mnemonic(ImportMnemonicParam): KeystoreResult
///
/// create a new hd keystore by mnemonic
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImportMnemonicParam {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub password_hint: ::prost::alloc::string::String,
    #[prost(bool, tag = "6")]
    pub overwrite: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImportPrivateKeyResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub source: ::prost::alloc::string::String,
    #[prost(int64, tag = "6")]
    pub created_at: i64,
    #[prost(string, repeated, tag = "7")]
    pub identified_chain_types: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "8")]
    pub identified_network: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub identified_curve: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub source_fingerprint: ::prost::alloc::string::String,
}
///
/// derive new accounts from a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveAccountsParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "4")]
    pub derivations: ::prost::alloc::vec::Vec<derive_accounts_param::Derivation>,
    #[prost(oneof = "derive_accounts_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<derive_accounts_param::Key>,
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
        #[prost(string, tag = "7")]
        pub bech32_prefix: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
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
/// export the mnemonic from a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportMnemonicResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub mnemonic: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportPrivateKeyResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub private_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportJsonResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub json: ::prost::alloc::string::String,
}
/// FUNCTION: import_private_key(ImportPrivateKeyParam): KeystoreResult
///
/// create a new private key keystore by a private key
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImportPrivateKeyParam {
    #[prost(string, tag = "1")]
    pub private_key: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub password_hint: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub network: ::prost::alloc::string::String,
    #[prost(bool, tag = "6")]
    pub overwrite: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExistsMnemonicParam {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExistsPrivateKeyParam {
    #[prost(string, tag = "1")]
    pub private_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExistsJsonParam {
    #[prost(string, tag = "1")]
    pub json: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExistsKeystoreResult {
    #[prost(bool, tag = "1")]
    pub is_exists: bool,
    #[prost(string, tag = "2")]
    pub id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImportJsonParam {
    #[prost(string, tag = "1")]
    pub json: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(bool, tag = "3")]
    pub overwrite: bool,
}
/// FUNCTION: sign_tx(SignParam)
///
/// Sign transaction. This api is used for sign any chain_type, you should build the right TxInput instance and
/// put it in the `input` field
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub seg_wit: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "9")]
    pub input: ::core::option::Option<::prost_types::Any>,
    #[prost(oneof = "sign_param::Key", tags = "2, 3")]
    pub key: ::core::option::Option<sign_param::Key>,
}
/// Nested message and enum types in `SignParam`.
pub mod sign_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "2")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        DerivedKey(::prost::alloc::string::String),
    }
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
    #[prost(oneof = "sign_authentication_message_param::Key", tags = "4, 5")]
    pub key: ::core::option::Option<sign_authentication_message_param::Key>,
}
/// Nested message and enum types in `SignAuthenticationMessageParam`.
pub mod sign_authentication_message_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "4")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "5")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignAuthenticationMessageResult {
    #[prost(uint64, tag = "1")]
    pub access_time: u64,
    #[prost(string, tag = "2")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MnemonicToPublicKeyParam {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub encoding: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MnemonicToPublicKeyResult {
    #[prost(string, tag = "1")]
    pub public_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MigrateKeystoreParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub network: ::prost::alloc::string::String,
    #[prost(oneof = "migrate_keystore_param::Key", tags = "3, 4")]
    pub key: ::core::option::Option<migrate_keystore_param::Key>,
}
/// Nested message and enum types in `MigrateKeystoreParam`.
pub mod migrate_keystore_param {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(string, tag = "3")]
        Password(::prost::alloc::string::String),
        #[prost(string, tag = "4")]
        DerivedKey(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MigrateKeystoreResult {
    #[prost(bool, tag = "1")]
    pub is_existed: bool,
    #[prost(string, tag = "2")]
    pub existed_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub keystore: ::core::option::Option<KeystoreResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScanKeystoresResult {
    #[prost(message, repeated, tag = "1")]
    pub hd_keystores: ::prost::alloc::vec::Vec<KeystoreResult>,
    #[prost(message, repeated, tag = "2")]
    pub private_key_keystores: ::prost::alloc::vec::Vec<ImportPrivateKeyResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LegacyKeystoreResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub source: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub created_at: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "5")]
    pub accounts: ::prost::alloc::vec::Vec<AccountResponse>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScanLegacyKeystoresResult {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub ipfs_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub source: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "5")]
    pub keystores: ::prost::alloc::vec::Vec<LegacyKeystoreResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupResult {
    #[prost(string, tag = "1")]
    pub original: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MarkIdentityWalletsParam {
    #[prost(string, repeated, tag = "1")]
    pub ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "2")]
    pub source: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadKeystoreMnemonicPathResult {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyDerivedKeyParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub derived_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DerivedKeyResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub derived_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CacheDerivedKeyResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(bool, tag = "2")]
    pub enable_derived_key: bool,
    #[prost(string, tag = "3")]
    pub mode: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WalletId {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BiometricModeResult {
    #[prost(string, tag = "1")]
    pub mode: ::prost::alloc::string::String,
}
