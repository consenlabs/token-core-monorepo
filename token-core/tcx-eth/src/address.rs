use crate::Result;
use anyhow::anyhow;
use ethereum_types::H160;
use std::str::FromStr;
use tcx_common::FromHex;
use tcx_constants::CoinInfo;
use tcx_keystore::Address;
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct EthAddress(H160);

pub fn to_checksum(addr: &ethereum_types::Address, chain_id: Option<u8>) -> String {
    wallet_core_common::eth::checksum_address_bytes(addr.as_bytes(), chain_id)
        .expect("ethereum address is 20 bytes")
}

pub fn pubkey_to_address(compressed_pubkey: &[u8]) -> String {
    let addr_bytes =
        wallet_core_common::eth::address_bytes_from_uncompressed_pubkey(compressed_pubkey)
            .expect("secp256k1 public key is uncompressed");
    format!("0x{}", hex::encode(addr_bytes))
}

impl Address for EthAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let bytes = public_key.as_secp256k1()?.to_uncompressed();
        let addr_bytes = wallet_core_common::eth::address_bytes_from_uncompressed_pubkey(&bytes)
            .expect("secp256k1 public key is uncompressed");
        let addr = H160::from_slice(&addr_bytes);
        Ok(EthAddress(addr))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        is_valid_address(address)
    }
}

impl std::fmt::Display for EthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&to_checksum(&self.0, None))
    }
}

impl FromStr for EthAddress {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !is_valid_address(s) {
            return Err(anyhow!("invalid_eth_address"));
        }

        let bytes = Vec::from_hex(&s[2..])?;
        let addr = H160::from_slice(&bytes);
        Ok(EthAddress(addr))
    }
}

pub fn is_valid_address(address: &str) -> bool {
    wallet_core_common::eth::is_valid_address(address)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::address::EthAddress;
    use tcx_common::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::Address;
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, TypedPrivateKey};

    use super::is_valid_address;

    #[test]
    fn test_eth_address() {
        let private_key_bytes =
            Vec::from_hex("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6")
                .unwrap();
        let mut secp256k1_private_key =
            Secp256k1PrivateKey::from_slice(private_key_bytes.as_slice()).unwrap();
        secp256k1_private_key.0.compressed = false;
        let typed_public_key = TypedPrivateKey::Secp256k1(secp256k1_private_key).public_key();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "ETHEREUM".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "testnet".to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };
        let address = EthAddress::from_public_key(&typed_public_key, &coin_info).unwrap();
        assert_eq!(
            address.to_string(),
            "0xef678007D18427E6022059Dbc264f27507CD1ffC"
        );

        let is_valid =
            EthAddress::is_valid("0xef678007d18427e6022059dbc264f27507cd1ffc", &coin_info);
        assert!(is_valid);

        assert!(EthAddress::is_valid(
            "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5",
            &coin_info
        ));
        assert!(!EthAddress::is_valid(
            "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfE5",
            &coin_info
        ));
    }

    #[test]
    fn test_eth_address_from_str() {
        let address = EthAddress::from_str("0xef678007D18427E6022059Dbc264f27507CD1ffC").unwrap();
        assert_eq!(
            address.to_string(),
            "0xef678007D18427E6022059Dbc264f27507CD1ffC"
        );

        let result = EthAddress::from_str("0xef678007D18427E6022059Dbc264f27507CD1ffCXX");
        assert_eq!(
            result.err().unwrap().to_string(),
            "invalid_eth_address".to_string()
        );

        let result = EthAddress::from_str("0xef678007D18427E6022059Dbc264f27507CD1ffc");
        assert_eq!(
            result.err().unwrap().to_string(),
            "invalid_eth_address".to_string()
        );
    }

    #[test]
    fn test_invalid_address() {
        let invalid_address_list = [
            "ef678007D18427E6022059Dbc264f27507CD1ffC",
            "0xef678007D18427E6022059Dbc264f27507CD1ffCXX",
            "0xef678007D18427E6022059Dbc264f27507CD1ff#",
        ];
        for address in invalid_address_list.iter() {
            let result = is_valid_address(address);
            assert!(!result);
        }
    }

    #[test]
    fn test_valid_address() {
        let address_list = [
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
            "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303",
        ];
        for address in address_list.iter() {
            let result = is_valid_address(address);
            assert!(result);
        }
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "ETHEREUM".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            contract_code: "".to_string(),
        };
        let address = EthAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "0xAc1ec44E4f0ca7D172B7803f6836De87Fb72b309");
    }
}
