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
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub data_to_sign: ::prost::alloc::vec::Vec<sign_hashes_param::DataToSign>,
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
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignHashesResult {
    #[prost(string, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignParamPoc {
    #[prost(string, tag = "3")]
    pub hash: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub derivation_path: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignResultPoc {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyDerivation {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub curve: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPublicKeysParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
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
pub struct GetExtendedPublicKeysParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub derivations: ::prost::alloc::vec::Vec<PublicKeyDerivation>,
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
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub curve: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
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
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncPrivateKeyFromSeedParam {
    #[prost(string, tag = "1")]
    pub seed: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncPrivateKeyFromSeedResult {
    #[prost(string, tag = "1")]
    pub priv_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncSignMusigParam {
    #[prost(string, tag = "1")]
    pub priv_key: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub bytes: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncSignMusigResult {
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncPrivateKeyToPubkeyHashParam {
    #[prost(string, tag = "1")]
    pub priv_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZksyncPrivateKeyToPubkeyHashResult {
    #[prost(string, tag = "1")]
    pub pub_key_hash: ::prost::alloc::string::String,
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
/// FUNCTION: hd_store_derive(HdStoreDeriveParam): DeriveAccountsResult
///
/// derive new accounts from a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveAccountsParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
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
        #[prost(string, tag = "7")]
        pub bech32_prefix: ::prost::alloc::string::String,
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
    pub extended_public_key: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub public_key: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub curve: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveAccountsResult {
    #[prost(message, repeated, tag = "1")]
    pub accounts: ::prost::alloc::vec::Vec<AccountResponse>,
}
/// FUNCTION: hd_store_export(ExportResult): ExistsKeystoreResult
///
/// export the mnemonic from a hd keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExportResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration = "KeyType", tag = "2")]
    pub r#type: i32,
    #[prost(string, tag = "3")]
    pub value: ::prost::alloc::string::String,
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
    #[prost(bool, tag = "5")]
    pub overwrite: bool,
    #[prost(string, tag = "6")]
    pub encoding: ::prost::alloc::string::String,
}
/// FUNCTION: private_key_store_export(PrivateKeyStoreExportParam): ExportResult
///
/// export the private key from a private key keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrivateKeyStoreExportParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub network: ::prost::alloc::string::String,
}
/// FUNCTION: keystore_common_exists(KeystoreCommonExistsParam): ExistsKeystoreResult
///
/// Check is there a keystore was generate by the special privateKey or mnemonic
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeystoreCommonExistsParam {
    #[prost(enumeration = "KeyType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub encoding: ::prost::alloc::string::String,
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
    #[prost(string, tag = "2")]
    pub encoding: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExistsKeystoreResult {
    #[prost(bool, tag = "1")]
    pub is_exists: bool,
    #[prost(string, tag = "2")]
    pub id: ::prost::alloc::string::String,
}
/// FUNCTION: keystore_common_accounts(KeystoreCommonAccountsParam): DeriveAccountsResult
///
/// List all accounts from the keystore
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeystoreCommonAccountsParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
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
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub network: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub seg_wit: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "4")]
    pub relative_paths: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub extended_public_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeriveSubAccountsResult {
    #[prost(string, repeated, tag = "1")]
    pub addresses: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub public_key: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoreDeleteParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub password: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoreDeleteResult {
    #[prost(bool, tag = "1")]
    pub is_success: bool,
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenerateMnemonicResult {
    #[prost(string, tag = "1")]
    pub mnemonic: ::prost::alloc::string::String,
}
/// only support two types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum KeyType {
    Mnemonic = 0,
    PrivateKey = 1,
}
impl KeyType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            KeyType::Mnemonic => "MNEMONIC",
            KeyType::PrivateKey => "PRIVATE_KEY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "MNEMONIC" => Some(Self::Mnemonic),
            "PRIVATE_KEY" => Some(Self::PrivateKey),
            _ => None,
        }
    }
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeystoreMigrationParam {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub tcx_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub password: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub derived_key: ::prost::alloc::string::String,
}
