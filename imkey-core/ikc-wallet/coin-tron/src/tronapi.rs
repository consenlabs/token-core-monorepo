#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxInput {
    #[prost(string, tag = "2")]
    pub raw_data: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxOutput {
    #[prost(string, tag = "1")]
    pub signature: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageInput {
    #[prost(string, tag = "2")]
    pub message: std::string::String,
    #[prost(bool, tag = "4")]
    pub is_hex: bool,
    #[prost(bool, tag = "5")]
    pub is_tron_header: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageOutput {
    #[prost(string, tag = "1")]
    pub signature: std::string::String,
}
