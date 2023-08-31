mod address;
mod keystore;
mod signer;
mod transaction;

pub use address::SubstrateAddress;
pub use keystore::{decode_substrate_keystore, encode_substrate_keystore, SubstrateKeystore};
pub use transaction::{
    ExportSubstrateKeystoreResult, SubstrateKeystoreParam, SubstrateRawTxIn, SubstrateTxOut,
};

pub(crate) const SIGNATURE_TYPE_SR25519: u8 = 0x01;
pub(crate) const PAYLOAD_HASH_THRESHOLD: usize = 256;

#[macro_use]
extern crate failure;
extern crate serde_json;

pub mod polkadot {
    use tcx_chain::{Account, Keystore};
    use tcx_constants::{CoinInfo, CurveType};

    pub const CHAINS: [&'static str; 2] = ["POLKADOT", "KUSAMA"];

    pub type Address = crate::SubstrateAddress;
    pub type TransactionInput = crate::transaction::SubstrateRawTxIn;
    pub type TransactionOutput = crate::transaction::SubstrateTxOut;

    pub fn enable_account(
        coin: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[CoinInfo {
            coin: coin.to_string(),
            derivation_path: format!("//{}//imToken/{}", coin.to_lowercase(), index),
            curve: CurveType::SubSr25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}
