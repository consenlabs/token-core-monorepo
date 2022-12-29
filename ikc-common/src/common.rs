#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignParam {
    #[prost(string, tag = "1")]
    pub chain_type: std::string::String,
    #[prost(string, tag = "2")]
    pub path: std::string::String,
    #[prost(string, tag = "3")]
    pub network: std::string::String,
    #[prost(message, optional, tag = "4")]
    pub input: ::std::option::Option<::prost_types::Any>,
    #[prost(string, tag = "5")]
    pub payment: std::string::String,
    #[prost(string, tag = "6")]
    pub receiver: std::string::String,
    #[prost(string, tag = "7")]
    pub sender: std::string::String,
    #[prost(string, tag = "8")]
    pub fee: std::string::String,
}
