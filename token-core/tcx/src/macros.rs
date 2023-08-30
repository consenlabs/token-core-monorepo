use std::str::FromStr;
use tcx_chain::{Address, Keystore, TransactionSigner};
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FakeInput {}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FakeOutput {}

impl TransactionSigner<FakeInput, FakeOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        _chain_type: &str,
        _address: &str,
        _input: &FakeInput,
    ) -> std::result::Result<FakeOutput, failure::Error> {
        Ok(FakeOutput {})
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FakeAddress();

impl Address for FakeAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> tcx_chain::Result<Self> {
        Ok(FakeAddress {})
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        false
    }
}

impl FromStr for FakeAddress {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(FakeAddress())
    }
}

impl ToString for FakeAddress {
    fn to_string(&self) -> String {
        "".to_string()
    }
}

macro_rules! use_chains {
    ($($chain:path),*) => {
        use crate::macros::FakeOutput;
        use crate::macros::FakeInput;
        use crate::macros::FakeAddress;

        fn sign_transaction_internal(params: &SignParam, keystore: &mut Keystore) -> std::result::Result<Vec<u8>, failure::Error> {
            type TransactionInput = FakeInput;
            type TransactionOutput = FakeOutput;

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
            type Address = FakeAddress;

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
