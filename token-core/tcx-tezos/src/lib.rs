pub mod address;
pub mod signer;
pub mod transaction;
use bitcoin::util::base58;
use tcx_common::FromHex;
use tcx_keystore::Result;
use tcx_primitive::{Ed25519PrivateKey, PrivateKey, PublicKey};

pub fn build_tezos_base58_private_key(sk: &str) -> Result<String> {
    //tezos private key prefix
    let edsk_prefix: [u8; 4] = [43, 246, 78, 7];

    //prefix + private key + public key
    let mut prefixed_sec_key_vec = vec![];
    prefixed_sec_key_vec.extend(&edsk_prefix);
    let ed25519_private_key =
        Ed25519PrivateKey::from_slice(Vec::from_hex(sk).unwrap().as_slice()).unwrap();
    prefixed_sec_key_vec.extend(&ed25519_private_key.to_bytes());
    prefixed_sec_key_vec.extend(&ed25519_private_key.public_key().to_bytes());

    Ok(base58::check_encode_slice(prefixed_sec_key_vec.as_slice()))
}

pub fn pars_tezos_private_key(private_key: &str) -> Result<Vec<u8>> {
    let data = base58::from_check(private_key)?;
    let pk = Ed25519PrivateKey::from_slice(&data[4..36])?;
    Ok(pk.to_bytes())
}

pub mod tezos {
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Account, Keystore};

    pub const CHAINS: [&'static str; 1] = ["TEZOS"];

    pub type Address = crate::address::TezosAddress;
    pub type TransactionInput = crate::transaction::TezosRawTxIn;
    pub type TransactionOutput = crate::transaction::TezosTxOut;

    pub fn enable_account(
        _: &str,
        index: u32,
        keystore: &mut Keystore,
    ) -> Result<Vec<Account>, failure::Error> {
        keystore.derive_coins::<Address>(&[CoinInfo {
            coin: "TEZOS".to_string(),
            derivation_path: format!("m/44'/1729'/{}'/0'", index),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        }])
    }
}

#[cfg(test)]
mod tests {

    use crate::{build_tezos_base58_private_key, pars_tezos_private_key};
    use tcx_common::ToHex;

    #[test]
    fn test_build_tezos_private_key() {
        let base58_prikey = build_tezos_base58_private_key(
            "5740dedadb610333de66ef2db2d91fd648fcbe419dff766f921ae97d536f94ce",
        )
        .unwrap();
        assert_eq!(base58_prikey, "edskRoRrqsGXLTjMwAtzLSx8G7s9ipibZQh6ponFhZYSReSwxwPo7qJCkPJoRjdUhz8Hj7uZhZaFp7F5yftHUYBpJwF2ZY6vAc");
    }

    #[test]
    fn test_pars_tezos_private_key() {
        let tezos_base58_sk = "edskRoRrqsGXLTjMwAtzLSx8G7s9ipibZQh6ponFhZYSReSwxwPo7qJCkPJoRjdUhz8Hj7uZhZaFp7F5yftHUYBpJwF2ZY6vAc";
        let parsing_result = pars_tezos_private_key(tezos_base58_sk).unwrap();
        assert_eq!(
            parsing_result.to_hex(),
            "5740dedadb610333de66ef2db2d91fd648fcbe419dff766f921ae97d536f94ce".to_string()
        );
    }
}
