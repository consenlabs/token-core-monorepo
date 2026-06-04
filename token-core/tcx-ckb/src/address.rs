use std::str::FromStr;
use tcx_constants::CoinInfo;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct CkbAddress(String);

impl Address for CkbAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let public_key = public_key.as_secp256k1()?.to_compressed();
        Ok(CkbAddress(
            wallet_core_common::ckb::address::short_address_from_pubkey(
                coin.network.as_str(),
                &public_key,
            )?,
        ))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        wallet_core_common::ckb::address::is_valid_address(address, coin.network.as_str())
    }
}

impl FromStr for CkbAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(CkbAddress(s.to_string()))
    }
}

impl ToString for CkbAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::address::CkbAddress;
    use std::str::FromStr;
    use tcx_common::FromHex;
    use tcx_keystore::Address;

    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{TypedPrivateKey, TypedPublicKey};

    #[test]
    fn pubkey_to_address() {
        let network_addresses = vec![
            ("TESTNET", "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83"),
            ("MAINNET", "ckb1qyqrdsefa43s6m882pcj53m4gdnj4k440axqdt9rtd"),
        ];
        for (network, address) in network_addresses {
            let coin_info = CoinInfo {
                chain_id: "".to_string(),
                coin: "NERVOS".to_string(),
                derivation_path: "".to_string(),
                curve: CurveType::SECP256k1,
                network: network.to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            };

            let pub_key = TypedPublicKey::from_slice(
                CurveType::SECP256k1,
                &Vec::from_hex(
                    "024a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01",
                )
                .unwrap(),
            )
            .unwrap();
            let addr = CkbAddress::from_public_key(&pub_key, &coin_info).unwrap();
            assert_eq!(addr.to_string(), address);
        }
    }

    #[test]
    fn test_address_is_valid() {
        let valid_addresses = vec![
            ("TESTNET", "ckt1qyqd5eyygtdmwdr7ge736zw6z0ju6wsw7rssu8fcve"),
            ("MAINNET", "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq"),
        ];
        for (network, address) in valid_addresses {
            let coin_info = CoinInfo {
                chain_id: "".to_string(),
                coin: "NERVOS".to_string(),
                derivation_path: "".to_string(),
                curve: CurveType::SECP256k1,
                network: network.to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            };
            assert!(CkbAddress::is_valid(address, &coin_info));
        }

        let invalid_addresses = vec![
            ("MAINNET", "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryg"),
            ("TESTNET", "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu85"),
        ];
        for (address, network) in invalid_addresses {
            let coin_info = CoinInfo {
                chain_id: "".to_string(),
                coin: "NERVOS".to_string(),
                derivation_path: "".to_string(),
                curve: CurveType::SECP256k1,
                network: network.to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            };
            assert!(!CkbAddress::is_valid(address, &coin_info));
        }
    }

    #[test]
    fn test_valid_address_data() {
        let invalid_address = vec![
            "ckt1qyzndsefa43s6m882pcj53m4gdnj4k440axqcth0hp",
            "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqqm65l9j",
            "ckt1qcqrdsefa43s6m882pcj53m4gdnj4k440axqyj7g8k",
            "test1qyqrdsefa43s6m882pcj53m4gdnj4k440axqpkzhhy",
        ];
        for invalid_address in invalid_address {
            let coin_info = CoinInfo {
                chain_id: "".to_string(),
                coin: "NERVOS".to_string(),
                derivation_path: "".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            };
            assert!(!CkbAddress::is_valid(invalid_address, &coin_info));
        }
    }

    #[test]
    fn test_address_from_str() {
        let expect_address = "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq";
        let ckb_address = CkbAddress::from_str(expect_address).unwrap();
        assert_eq!(ckb_address.to_string(), expect_address);
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "8a2a726c44e46d1efaa0f9c2a8efed932f0e96d6050b914fde762ee285e61feb";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "NERVOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };
        let address = CkbAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "ckb1qyqvfdgvtjxswncx8mq2wl0dp6hlp7nmvhdqcecnt6");
    }
}
