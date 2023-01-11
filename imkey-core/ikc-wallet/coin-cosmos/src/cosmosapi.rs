#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosmosTxInput {
    #[prost(string, tag = "1")]
    pub data: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosmosTxOutput {
    #[prost(string, tag = "1")]
    pub signature: std::string::String,
}
