use core::str::FromStr;

use bech32::{FromBase32, ToBase32, Variant};
use tcx_chain::{Address, ChainFactory, PublicKeyEncoder, Result};
use tcx_constants::CoinInfo;
use tcx_crypto::hash;
use tcx_primitive::TypedPublicKey;

// size of address
pub const LENGTH: usize = 20;
#[derive(PartialEq, Eq, Clone)]
pub struct AtomAddress(String);

impl Address for AtomAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let prefix = "cosmos";

        let pub_key_bytes = public_key.to_bytes();
        let mut bytes = [0u8; LENGTH];
        let pub_key_hash = hash::ripemd160(&hash::sha256(&pub_key_bytes));
        bytes.copy_from_slice(&pub_key_hash[..LENGTH]);

        Ok(AtomAddress(
            bech32::encode(prefix, bytes.to_base32(), Variant::Bech32)?.to_string(),
        ))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let ret = bech32::decode(address);
        if ret.is_ok() {
            let (hrp, data, _) = ret.unwrap();
            let data = Vec::from_base32(&data).unwrap();

            if hrp.as_str() != "cosmos" {
                return false;
            }

            if data.len() != 20 {
                return false;
            }

            return true;
        } else {
            return false;
        }
    }
}

impl FromStr for AtomAddress {
    type Err = failure::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(AtomAddress(s.to_string()))
    }
}

impl ToString for AtomAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

pub struct AtomPublicKeyEncoder();
impl PublicKeyEncoder for AtomPublicKeyEncoder {
    fn encode(&self, public_key: &[u8]) -> Result<String> {
        Ok(tcx_crypto::hex::bytes_to_hex(public_key))
    }
}

pub struct AtomChainFactory();
impl ChainFactory for AtomChainFactory {
    fn create_public_key_encoder(&self) -> Box<dyn PublicKeyEncoder> {
        Box::new(AtomPublicKeyEncoder {})
    }
}
#[cfg(test)]
mod tests {

    use crate::address::AtomAddress;
    use tcx_chain::Address;

    use tcx_constants::{CoinInfo, CurveType};
    use tcx_crypto::hex;
    use tcx_primitive::TypedPublicKey;

    fn get_test_coin() -> CoinInfo {
        CoinInfo {
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        }
    }

    #[test]
    fn test_pubkey_to_address() {
        let test_cases = vec![
            (
                "037a525043e79a9051d58214a9a2a70b657b3d49124dcd0acc4730df5f35d74b32",
                "cosmos1pt9904aqg739q6p9kgc2v0puqvj6atp0zsj70g",
            ),
            (
                "02ba66a84cf7839af172a13e7fc9f5e7008cb8bca1585f8f3bafb3039eda3c1fdd",
                "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl",
            ),
        ];

        for (sec_key, expected_addr) in test_cases {
            let pub_key = TypedPublicKey::from_slice(
                CurveType::SECP256k1,
                &hex::hex_to_bytes(sec_key).unwrap(),
            )
            .unwrap();

            let addr = AtomAddress::from_public_key(&pub_key, &get_test_coin()).unwrap();
            assert_eq!(addr.to_string(), expected_addr);
        }
    }

    #[test]
    fn test_address_is_valid() {
        let invalid_addresses = vec![
            "ckt1qyqd5eyygtdmwdr7ge736zw6z0ju6wsw7rssu8fcve",
            "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq",
        ];
        for addr in invalid_addresses {
            assert!(!AtomAddress::is_valid(addr, &get_test_coin()));
        }

        let valid_addresses = vec![
            "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl",
            "cosmos1pt9904aqg739q6p9kgc2v0puqvj6atp0zsj70g",
        ];
        for addr in valid_addresses {
            assert!(AtomAddress::is_valid(addr, &get_test_coin()));
        }
    }
}
