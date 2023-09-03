use std::str::FromStr;
use tcx_btc_kin::Error;
use tcx_chain::{Address, Keystore, TransactionSigner};
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnsupportedInput {}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnsupportedOutput {}

impl TransactionSigner<UnsupportedInput, UnsupportedOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        _chain_type: &str,
        _address: &str,
        _input: &UnsupportedInput,
    ) -> std::result::Result<UnsupportedOutput, failure::Error> {
        Err(Error::UnsupportedChain.into())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UnsupportedAddress();

impl Address for UnsupportedAddress {
    fn from_public_key(_public_key: &TypedPublicKey, _coin: &CoinInfo) -> tcx_chain::Result<Self> {
        Err(Error::UnsupportedChain.into())
    }

    fn is_valid(_address: &str, _coin: &CoinInfo) -> bool {
        false
    }
}

impl FromStr for UnsupportedAddress {
    type Err = failure::Error;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(Error::UnsupportedChain.into())
    }
}

impl ToString for UnsupportedAddress {
    fn to_string(&self) -> String {
        "".to_string()
    }
}

macro_rules! use_chains {
    ($($chain:path),+ $(,)?) => {
        use crate::macros::{UnsupportedInput, UnsupportedOutput, UnsupportedAddress};

        fn sign_transaction_internal(params: &SignParam, keystore: &mut Keystore) -> std::result::Result<Vec<u8>, failure::Error> {
            type TransactionInput = UnsupportedInput;
            type TransactionOutput = UnsupportedOutput;

            $({
                use $chain::*;
                if CHAINS.contains(&params.chain_type.as_str()) {
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

            Err(format_err!("unsupported chain type: {}", params.chain_type))
        }

        fn derive_account_internal(coin_info:&CoinInfo, keystore: &mut Keystore) -> Result<Account> {
            type Address = UnsupportedAddress;

            $({
                use $chain::*;
                if CHAINS.contains(&coin_info.coin.as_str()) {
                    return keystore.derive_coin::<Address>(coin_info)
                }
            })*

            Err(format_err!("unsupported chain type: {}", coin_info.coin))
        }
    };
}

pub(crate) use use_chains;
