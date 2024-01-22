use bitcoin::util::base58;
use std::str::FromStr;
use tcx_common::ripemd160;
use tcx_constants::CoinInfo;
use tcx_keystore::{keystore::PublicKeyEncoder, Address, Result};
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct EosAddress {}

#[derive(PartialEq, Eq, Clone)]
pub struct EosPublicKeyEncoder {}

impl PublicKeyEncoder for EosPublicKeyEncoder {
    fn encode(public_key: &TypedPublicKey, _coin_info: &CoinInfo) -> Result<String> {
        let pubkey_bytes = public_key.to_bytes();
        let hashed_bytes = ripemd160(&pubkey_bytes);
        let checksum = hashed_bytes[..4].to_vec();
        let mut bytes = vec![];
        bytes.extend_from_slice(&pubkey_bytes);
        bytes.extend_from_slice(&checksum);
        Ok(format!("EOS{}", base58::encode_slice(&bytes)))
    }
}

impl Address for EosAddress {
    fn from_public_key(_public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        Ok(EosAddress {})
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let r = EosAddress::from_str(address);
        r.is_ok()
    }
}

impl FromStr for EosAddress {
    type Err = anyhow::Error;
    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(EosAddress {})
    }
}

impl ToString for EosAddress {
    fn to_string(&self) -> String {
        "".to_string()
    }
}

#[cfg(test)]
mod tests {

    use crate::address::EosPublicKeyEncoder;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{Address, PublicKeyEncoder};
    use tcx_primitive::{PublicKey, Secp256k1PublicKey, TypedPrivateKey, TypedPublicKey};

    #[test]
    fn test_encode_public_key() {
        let tests = [
            (
                "0x037b5253c24ce2a293566f9e066051366cda5073e4a43b25f07c990d7c9ac0aab5",
                "EOS7mYcbf9BumHjUUCPoXh2nxzkipQZDQCZC7EmRq8cwB1exEYHfy",
            ),
            (
                "0x03f6a261f3b4d7c24014f2026b09ad409076c566b39b99b8e0a7196f391caec508",
                "EOS8hrUMSKjQZK4QsXLfAVTwmmD4nTfF9Lb11ZQN3zVYrdxhApgFr",
            ),
            (
                "0x03844a01522a26156df32b587d80df60d76072480e299c6d3241c7b2b929c07625",
                "EOS7qVgE5PF58jAV7HmFPNEAEdyZmE4UBasTRa7AZ1AhJGxYovBwc",
            ),
            (
                "0x035cda3171ba9107ec3f398c8e33b17803fd9d6a815ee5d544a71759455396319c",
                "EOS7Y8KPZQDMhDWjHaM3nWRWwYSoP75KpSatFbanKRPRaUKDWi2UA",
            ),
        ];

        for i in tests {
            let bytes = Vec::from_0x_hex(i.0).unwrap();
            let k1_pub_key = Secp256k1PublicKey::from_slice(&bytes).unwrap();
            let typed_pub_key = TypedPublicKey::Secp256k1(k1_pub_key);
            assert_eq!(
                EosPublicKeyEncoder::encode(&typed_pub_key, &CoinInfo::default()).unwrap(),
                i.1
            );
        }
    }

    #[test]
    fn cross_test_tw() {
        let tests = [
            (
                "0x8e14ef506fee5e0aaa32f03a45242d32d0eb993ffe25ce77542ef07219db667c",
                "EOS6TFKUKVvtvjRq9T4fV9pdxNUuJke92nyb4rzSFtZfdR5ssmVuY",
            ),
            (
                "0xe2bfd815c5923f404388a3257aa5527f0f52e92ce364e1e26a04d270c901edda",
                "EOS5YtaCcbPJ3BknNBTDezE9eJoGNnAVuUwT8bnxhSRS5dqRvyfxr",
            ),
        ];

        for i in tests {
            let bytes = Vec::from_0x_hex(i.0).unwrap();
            // let k1_pub_key = Secp256k1PublicKey::from_slice(&bytes).unwrap();
            // let typed_pub_key = TypedPublicKey::Secp256k1(k1_pub_key);
            let typed_pub_key = TypedPrivateKey::from_slice(CurveType::SECP256k1, &bytes)
                .unwrap()
                .public_key();
            assert_eq!(
                EosPublicKeyEncoder::encode(&typed_pub_key, &CoinInfo::default()).unwrap(),
                i.1
            );
        }
    }
}
