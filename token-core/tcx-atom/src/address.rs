use anyhow::anyhow;
use core::str::FromStr;

use crate::hrps::CHAIN_ID_HRP_MAP;
use bech32::{FromBase32, ToBase32, Variant};
use tcx_common::{ripemd160, sha256};
use tcx_constants::CoinInfo;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;

// size of address
pub const LENGTH: usize = 20;

fn find_hrp(chain_id: &str) -> Result<String> {
    let map = CHAIN_ID_HRP_MAP.read().unwrap();
    let embed_hrp = map.get(chain_id);

    return if embed_hrp.is_some() {
        Ok(embed_hrp.unwrap().to_string())
    } else {
        Err(anyhow!("unknown_chain_id"))
    };
}

#[derive(PartialEq, Eq, Clone)]
pub struct AtomAddress(String);

impl Address for AtomAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let pub_key_bytes = public_key.to_bytes();
        let mut bytes = [0u8; LENGTH];
        let pub_key_hash = ripemd160(&sha256(&pub_key_bytes));
        bytes.copy_from_slice(&pub_key_hash[..LENGTH]);
        let hrp = find_hrp(&coin.chain_id)?;

        Ok(AtomAddress(bech32::encode(
            &hrp,
            bytes.to_base32(),
            Variant::Bech32,
        )?))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let ret = bech32::decode(address);
        if let Ok(val) = ret {
            let (hrp, data, _) = val;
            let data = Vec::from_base32(&data).unwrap();

            if data.len() != 20 {
                return false;
            }
            true
        } else {
            false
        }
    }
}

impl FromStr for AtomAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(AtomAddress(s.to_string()))
    }
}

impl ToString for AtomAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::address::AtomAddress;
    use anyhow::anyhow;
    use std::str::FromStr;
    use tcx_keystore::Address;

    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{TypedPrivateKey, TypedPublicKey};

    fn get_test_coin() -> CoinInfo {
        CoinInfo {
            chain_id: "cosmoshub-4".to_string(),
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
            let pub_key =
                TypedPublicKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(sec_key).unwrap())
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

    #[test]
    fn test_address_is_invalid() {
        let valid_addresses = vec![
            "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhll",
            "cosmos1pt9904aqg739q6p9kgc2v0puqvj6atqxw0dax",
        ];
        for addr in valid_addresses {
            assert!(!AtomAddress::is_valid(addr, &get_test_coin()));
        }
    }

    #[test]
    fn test_address_from_str() {
        let address = "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl";
        let atom_address = AtomAddress::from_str(address).unwrap();
        assert_eq!(atom_address.to_string(), address);
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let coin_info = CoinInfo {
            chain_id: "cosmoshub-4".to_string(),
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let address = AtomAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02");
    }

    #[test]
    fn test_sub_net() {
        let pub_key_hex = "0317f65e6736ad182b47e386af40af0f26fb524bdd94e172a6145a6603d65a44b2";
        let pub_key =
            TypedPublicKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(pub_key_hex).unwrap())
                .unwrap();

        let testcase = [
            (
                "dydx",
                "dydx-mainnet-1",
                "m/44'/118'/0'/0/0",
                "dydx1m566v5rcklnac8vc0dftfu4lnvznhlu7yg830z",
            ),
            (
                "osmo",
                "osmosis-1",
                "m/44'/118'/0'/0/0",
                "osmo1m566v5rcklnac8vc0dftfu4lnvznhlu79269e8",
            ),
            (
                "neutron",
                "neutron-1",
                "m/44'/118'/0'/0/0",
                "neutron1m566v5rcklnac8vc0dftfu4lnvznhlu7fwqh4j",
            ),
            (
                "stride",
                "stride-1",
                "m/44'/118'/0'/0/0",
                "stride1m566v5rcklnac8vc0dftfu4lnvznhlu7w6ffme",
            ),
        ];
        for (hrp, chain_id, path, expected_addr) in testcase {
            let coin_info = CoinInfo {
                chain_id: chain_id.to_string(),
                coin: "COSMOS".to_string(),
                derivation_path: path.to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let address = AtomAddress::from_public_key(&pub_key, &coin_info)
                .unwrap()
                .to_string();
            assert_eq!(address, expected_addr)
        }
    }

    #[test]
    fn test_chain_id_hrp_verify() {
        let prv_str = "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let coin_info = CoinInfo {
            chain_id: "cosmoshub-4".to_string(),
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let address = AtomAddress::from_public_key(&pub_key, &coin_info);

        assert_eq!(
            format!("{}", address.unwrap().to_string()),
            "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02"
        );

        let coin_info = CoinInfo {
            chain_id: "unknown-chainid".to_string(),
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let address = AtomAddress::from_public_key(&pub_key, &coin_info);
        assert_eq!(format!("{}", address.err().unwrap()), "unknown_chain_id");

        let coin_info = CoinInfo {
            chain_id: "cosmoshub-4".to_string(),
            coin: "COSMOS".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let address = AtomAddress::from_public_key(&pub_key, &coin_info);
        assert_eq!(
            address.unwrap().to_string(),
            "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02"
        );
    }
}
