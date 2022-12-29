#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTxInput {
    #[prost(string, tag = "1")]
    pub nonce: std::string::String,
    #[prost(string, tag = "2")]
    pub gas_price: std::string::String,
    #[prost(string, tag = "3")]
    pub gas_limit: std::string::String,
    #[prost(string, tag = "4")]
    pub to: std::string::String,
    #[prost(string, tag = "5")]
    pub value: std::string::String,
    #[prost(string, tag = "6")]
    pub data: std::string::String,
    #[prost(string, tag = "7")]
    pub chain_id: std::string::String,
    #[prost(string, tag = "8")]
    pub r#type: std::string::String,
    #[prost(string, tag = "9")]
    pub max_fee_per_gas: std::string::String,
    #[prost(string, tag = "10")]
    pub max_priority_fee_per_gas: std::string::String,
    #[prost(message, repeated, tag = "11")]
    pub access_list: ::std::vec::Vec<AccessList>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessList {
    #[prost(string, tag = "1")]
    pub address: std::string::String,
    #[prost(string, repeated, tag = "2")]
    pub storage_keys: ::std::vec::Vec<std::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthTxOutput {
    #[prost(string, tag = "1")]
    pub signature: std::string::String,
    #[prost(string, tag = "2")]
    pub tx_hash: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthMessageInput {
    #[prost(string, tag = "1")]
    pub message: std::string::String,
    #[prost(bool, tag = "2")]
    pub is_personal_sign: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: std::string::String,
}
