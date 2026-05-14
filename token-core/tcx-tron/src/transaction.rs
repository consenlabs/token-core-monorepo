/// FUNCTION: sign_tx(SignParam{input: TronTxInput}): TronTxOutput
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxInput {
    /// hex string
    #[prost(string, tag = "1")]
    pub raw_data: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronTxOutput {
    /// hex string
    #[prost(string, repeated, tag = "1")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// FUNCTION: tron_sign_message(SignParam): TronMessageOutput
///
/// This api use a common struct named `SignParam`, you should
/// build the `TronMessageInput` and put it in the `input` field
///
/// Message signing versions:
/// - version = 1: V1 format with header "\x19TRON Signed Message:\n32"
/// - version = 2: V2 format with header "\x19TRON Signed Message:\n"
/// - version = 3: TIP-712 format with header "\x19\x01"
///
/// TIP-712 (EIP-712) Structured Data Signing:
/// Version = 3 requires header "TRON" (ASCII, case-insensitive). Other header
/// values are rejected.
/// When using version = 3 (header = "TRON"), the `value` field MUST be the
/// 64-byte concatenation of `domainSeparator` and `hashStruct(message)`,
/// i.e. the pre-image (without the "\x19\x01" prefix). The signer will
/// internally:
///    1. Prepend the "\x19\x01" prefix
///    2. Compute keccak256("\x19\x01" || domainSeparator || hashStruct(message))
///    3. ECDSA-sign the resulting 32-byte digest
///
/// In other words, the caller is responsible for computing
/// `domainSeparator` and `hashStruct(message)` (each 32 bytes) and passing
/// their raw concatenation. The caller MUST NOT pre-hash this value.
///
/// Example TIP-712 input (value length = 0x prefix + 128 hex chars = 64 bytes):
/// {
///    "value": "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090fc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
///    "header": "TRON",
///    "version": 3
/// }
///
/// Reference: <https://github.com/tronprotocol/tips/blob/master/tip-712.md>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageInput {
    /// The message to sign
    /// - For version 1/2: Raw message string or hex string (with 0x prefix)
    /// - For version 3 (TIP-712): MUST be a 64-byte hex string
    ///    (128 hex chars with 0x prefix), formed by
    ///    `domainSeparator (32 bytes) || hashStruct(message) (32 bytes)`.
    ///    Do NOT pre-hash this value.
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
    /// Header type: "TRON", "ETH", or "NONE"
    /// - "TRON": Use TRON-specific message prefix (required when version = 3)
    /// - "ETH": Use Ethereum message prefix
    /// - "NONE": Use Ethereum message prefix
    #[prost(string, tag = "2")]
    pub header: ::prost::alloc::string::String,
    /// Version: 1 (V1), 2 (V2), or 3 (TIP-712; header must be TRON)
    #[prost(uint32, tag = "3")]
    pub version: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TronMessageOutput {
    /// hex string with 0x prefix, 65 bytes (r: 32 bytes, s: 32 bytes, v: 1 byte)
    #[prost(string, tag = "1")]
    pub signature: ::prost::alloc::string::String,
}
