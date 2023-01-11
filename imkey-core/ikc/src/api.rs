/// Action Wrapper
/// There is a `call_imkey_api` method in tcx which act as a endpoint like RPC. It accepts a `ImkeyAction` param which method field is
/// the real action and param field is the real param of that method.
/// When an error occurred, the `call_imkey_api` will return a `Response` which isSuccess field be false and error field is the reason
/// which cause the error.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ImkeyAction {
    #[prost(string, tag = "1")]
    pub method: std::string::String,
    #[prost(message, optional, tag = "2")]
    pub param: ::std::option::Option<::prost_types::Any>,
}
/// A common response when error occurred.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorResponse {
    #[prost(bool, tag = "1")]
    pub is_success: bool,
    #[prost(string, tag = "2")]
    pub error: std::string::String,
}
///A commonresponse when successfully ended.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommonResponse {
    #[prost(string, tag = "1")]
    pub result: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressParam {
    #[prost(string, tag = "1")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "2")]
    pub path: std::string::String,
    #[prost(string, tag = "3")]
    pub network: std::string::String,
    #[prost(bool, tag = "4")]
    pub is_seg_wit: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressResult {
    #[prost(string, tag = "1")]
    pub path: std::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "3")]
    pub address: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubKeyParam {
    #[prost(string, tag = "1")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "2")]
    pub path: std::string::String,
    #[prost(string, tag = "3")]
    pub network: std::string::String,
    #[prost(string, tag = "4")]
    pub is_seg_wit: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubKeyResult {
    #[prost(string, tag = "1")]
    pub path: std::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "3")]
    pub pub_key: std::string::String,
    #[prost(string, tag = "4")]
    pub derived_mode: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalAddress {
    #[prost(string, tag = "1")]
    pub address: std::string::String,
    #[prost(string, tag = "2")]
    pub derived_path: std::string::String,
    #[prost(string, tag = "3")]
    pub r#type: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinWallet {
    #[prost(string, tag = "1")]
    pub path: std::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "3")]
    pub address: std::string::String,
    #[prost(string, tag = "4")]
    pub enc_x_pub: std::string::String,
    #[prost(message, optional, tag = "5")]
    pub external_address: ::std::option::Option<ExternalAddress>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EosWallet {
    #[prost(string, tag = "1")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "2")]
    pub address: std::string::String,
    #[prost(message, repeated, tag = "3")]
    pub public_keys: ::std::vec::Vec<eos_wallet::PubKeyInfo>,
}
pub mod eos_wallet {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PubKeyInfo {
        #[prost(string, tag = "1")]
        pub path: std::string::String,
        #[prost(string, tag = "2")]
        pub derived_mode: std::string::String,
        #[prost(string, tag = "3")]
        pub public_key: std::string::String,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalAddressParam {
    #[prost(string, tag = "1")]
    pub path: std::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "3")]
    pub network: std::string::String,
    #[prost(string, tag = "4")]
    pub seg_wit: std::string::String,
    #[prost(int32, tag = "5")]
    pub external_idx: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitImKeyCoreXParam {
    #[prost(string, tag = "1")]
    pub file_dir: std::string::String,
    #[prost(string, tag = "2")]
    pub xpub_common_key: std::string::String,
    #[prost(string, tag = "3")]
    pub xpub_common_iv: std::string::String,
    #[prost(bool, tag = "4")]
    pub is_debug: bool,
    #[prost(string, tag = "5")]
    pub system: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcForkWallet {
    #[prost(string, tag = "1")]
    pub path: std::string::String,
    #[prost(string, tag = "2")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "3")]
    pub address: std::string::String,
    #[prost(string, tag = "4")]
    pub enc_x_pub: std::string::String,
}
