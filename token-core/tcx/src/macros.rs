use std::str::FromStr;
use tcx_chain::{Address, Keystore, MessageSigner, TransactionSigner};
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MockTransactionInput {}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MockTransactionOutput {}

impl TransactionSigner<MockTransactionInput, MockTransactionOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        _chain_type: &str,
        _address: &str,
        _input: &MockTransactionInput,
    ) -> std::result::Result<MockTransactionOutput, failure::Error> {
        Err(format_err!("unsupported_chain"))
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MockMessageInput {}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MockMessageOutput {}

impl MessageSigner<MockMessageInput, MockMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        symbol: &str,
        address: &str,
        message: &MockMessageInput,
    ) -> tcx_chain::Result<MockMessageOutput> {
        Err(format_err!("unsupported_chain"))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MockAddress();

impl Address for MockAddress {
    fn from_public_key(_public_key: &TypedPublicKey, _coin: &CoinInfo) -> tcx_chain::Result<Self> {
        Err(format_err!("unsupported_chain"))
    }

    fn is_valid(_address: &str, _coin: &CoinInfo) -> bool {
        false
    }
}

impl FromStr for MockAddress {
    type Err = failure::Error;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(format_err!("unsupported_chain"))
    }
}

impl ToString for MockAddress {
    fn to_string(&self) -> String {
        "".to_string()
    }
}

macro_rules! use_chains {
    ($($chain:path),+ $(,)?) => {
        use crate::macros::{MockTransactionInput, MockTransactionOutput, MockAddress, MockMessageInput, MockMessageOutput};

        fn sign_transaction_internal(params: &SignParam, keystore: &mut Keystore) -> std::result::Result<Vec<u8>, failure::Error> {
            type TransactionInput = MockTransactionInput;
            type TransactionOutput = MockTransactionOutput;

            let faker_input = std::any::TypeId::of::<MockTransactionInput>();

            $({
                use $chain::*;

                if CHAINS.contains(&params.chain_type.as_str()) && std::any::TypeId::of::<TransactionInput>() != faker_input {
                    let input: TransactionInput = TransactionInput::decode(
                        params
                            .input
                            .as_ref()
                            .expect("tx_input")
                            .value
                            .clone()
                            .as_slice(),
                    )
                    .expect("TransactionInput");
                    let signed_tx: TransactionOutput = keystore.sign_transaction(&params.chain_type, &params.address, &input)?;

                    return encode_message(signed_tx)
                }
            })*

            Err(format_err!("unsupported_chain"))
        }

        fn derive_account_internal(coin_info:&CoinInfo, keystore: &mut Keystore) -> Result<Account> {
            type Address = MockAddress;
            let faker_address = std::any::TypeId::of::<MockAddress>();

            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) && std::any::TypeId::of::<Address>() != faker_address {
                    return keystore.derive_coin::<Address>(coin_info)
                }
            })*

            Err(format_err!("unsupported_chain"))
        }

        fn sign_message_internal(params:&SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
            type MessageInput = MockMessageInput;
            type MessageOutput = MockMessageOutput;

            let faker_input = std::any::TypeId::of::<MockMessageInput>();

            $({
                use $chain::*;
                if CHAINS.contains(&params.chain_type.as_str()) && std::any::TypeId::of::<MessageInput>() != faker_input {
                    let input: MessageInput = MessageInput::decode(
                        params
                            .input
                            .as_ref()
                            .expect("message_input")
                            .value
                            .clone()
                            .as_slice(),
                    )
                    .expect("MessageInput");

                    let signed_message: MessageOutput = keystore.sign_message(&params.chain_type, &params.address, &input)?;
                    return encode_message(signed_message)
                }
            })*

            Err(format_err!("unsupported_chain"))
        }
    };
}

pub(crate) use use_chains;