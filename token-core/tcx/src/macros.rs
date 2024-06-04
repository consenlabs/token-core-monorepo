use std::str::FromStr;

use anyhow::anyhow;

use tcx_constants::CoinInfo;
use tcx_keystore::{
    Address, Keystore, MessageSigner, PublicKeyEncoder, SignatureParameters, TransactionSigner,
};
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
        _sign_param: &SignatureParameters,
        _input: &MockTransactionInput,
    ) -> std::result::Result<MockTransactionOutput, anyhow::Error> {
        Err(anyhow!("unsupported_chain"))
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
        _sign_param: &SignatureParameters,
        _message: &MockMessageInput,
    ) -> tcx_keystore::Result<MockMessageOutput> {
        Err(anyhow!("unsupported_chain"))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MockAddress();

impl Address for MockAddress {
    fn from_public_key(
        _public_key: &TypedPublicKey,
        _coin: &CoinInfo,
    ) -> tcx_keystore::Result<Self> {
        Err(anyhow!("unsupported_chain"))
    }

    fn is_valid(_address: &str, _coin: &CoinInfo) -> bool {
        false
    }
}

impl FromStr for MockAddress {
    type Err = anyhow::Error;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(anyhow!("unsupported_chain"))
    }
}

impl ToString for MockAddress {
    fn to_string(&self) -> String {
        "".to_string()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MockPublicKeyEncoder();

impl PublicKeyEncoder for MockPublicKeyEncoder {
    fn encode(_public_key: &TypedPublicKey, _coin_info: &CoinInfo) -> tcx_keystore::Result<String> {
        Err(anyhow!("unsupported_chain"))
    }
}

macro_rules! use_chains {
    ($($chain:path),+ $(,)?) => {
        use tcx_keystore::PublicKeyEncoder;
        use crate::macros::{MockTransactionInput, MockTransactionOutput, MockAddress, MockPublicKeyEncoder, MockMessageInput, MockMessageOutput};

        #[allow(dead_code)]
        fn sign_transaction_internal(params: &SignParam, keystore: &mut Keystore) -> std::result::Result<Vec<u8>, anyhow::Error> {
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
                    let curve = CurveType::from_str(&params.curve);
                    let sign_params = SignatureParameters {
                        chain_type: params.chain_type.to_string(),
                        derivation_path: params.path.to_string(),
                        network: params.network.to_string(),
                        seg_wit: params.seg_wit.to_string(),
                        curve,

                    };
                    let signed_tx: TransactionOutput = keystore.sign_transaction(&sign_params, &input)?;

                    return encode_message(signed_tx)
                }
            })*

            Err(anyhow!("unsupported_chain"))
        }

        #[allow(dead_code)]
        fn derive_account_internal(coin_info:&CoinInfo, keystore: &mut Keystore) -> Result<Account> {
            type Address = MockAddress;
            let faker_address = std::any::TypeId::of::<MockAddress>();

            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) && std::any::TypeId::of::<Address>() != faker_address {
                    return keystore.derive_coin::<Address>(coin_info)
                }
            })*

            Err(anyhow!("unsupported_chain"))
        }

        #[allow(dead_code)]
        fn private_key_to_account_internal(coin_info:&CoinInfo, sec_key: &[u8]) -> Result<Account> {
            type Address = MockAddress;
            let faker_address = std::any::TypeId::of::<MockAddress>();

            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) && std::any::TypeId::of::<Address>() != faker_address {
                    return tcx_keystore::private_key_to_account::<Address>(coin_info, sec_key)
                }
            })*

            Err(anyhow!("unsupported_chain"))
        }

        #[allow(dead_code)]
        fn derive_sub_account(xpub: &TypedDeterministicPublicKey, coin_info:&CoinInfo) -> Result<Account> {
            type Address = MockAddress;
            let faker_address = std::any::TypeId::of::<MockAddress>();

            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) && std::any::TypeId::of::<Address>() != faker_address {
                    return Keystore::derive_sub_account::<Address>(xpub, coin_info)
                }
            })*

            Err(anyhow!("unsupported_chain"))
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
                let curve = CurveType::from_str(&params.curve);
                let sign_params = SignatureParameters {
                    chain_type: params.chain_type.to_string(),
                    derivation_path: params.path.to_string(),
                    network: params.network.to_string(),
                    seg_wit: params.seg_wit.to_string(),
                    curve,
                };
                    let signed_message: MessageOutput = keystore.sign_message(&sign_params, &input)?;
                    return encode_message(signed_message)
                }
            })*

            Err(anyhow!("unsupported_chain"))
        }

        fn encode_public_key_internal(public_key: &TypedPublicKey, coin_info:&CoinInfo,) -> Result<String> {
            type PubKeyEncoder = MockPublicKeyEncoder;
            let faker_encoder = std::any::TypeId::of::<MockPublicKeyEncoder>();
            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) && std::any::TypeId::of::<PubKeyEncoder>() != faker_encoder {
                    return PubKeyEncoder::encode(&public_key, coin_info)
                }
            })*

            return Ok(public_key.to_bytes().to_0x_hex())
        }
    };
}

pub(crate) use use_chains;

macro_rules! impl_to_key {
    ($type: ty) => {
        impl From<$type> for tcx_crypto::Key {
            fn from(key: $type) -> Self {
                match key {
                    <$type>::Password(password) => Self::Password(password),
                    <$type>::DerivedKey(derived_key) => Self::DerivedKey(derived_key),
                }
            }
        }
    };
}

pub(crate) use impl_to_key;
