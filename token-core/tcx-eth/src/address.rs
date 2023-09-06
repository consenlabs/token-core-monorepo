use crate::Result;
use ethers::utils::ConversionError::InvalidAddressChecksum;
use failure::format_err;
use regex::Regex;
use std::str::FromStr;
use tcx_chain::Address;
use tcx_common::keccak256;
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct EthAddress(Vec<u8>);

impl Address for EthAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let bytes = public_key.as_secp256k1()?.to_uncompressed();
        let pubkey_hash = keccak256(bytes[1..].as_ref());
        let addr_bytes = pubkey_hash[12..].to_vec();
        Ok(EthAddress(addr_bytes))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        is_valid_address(address)
    }
}

impl ToString for EthAddress {
    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

impl FromStr for EthAddress {
    type Err = failure::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !is_valid_address(s) {
            return Err(format_err!("invalid_address"));
        }

        let bytes = hex::decode(&s[2..])?;
        Ok(EthAddress(bytes))
    }
}

pub fn is_valid_address(address: &str) -> bool {
    if address.len() != 42 && !address.starts_with("0x") {
        return false;
    }

    let eth_addr_regex = Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap();
    if !eth_addr_regex.is_match(address) {
        return false;
    }

    if address.to_lowercase() == address {
        return true;
    }

    let address = &address[2..];
    let lower_address_bytes = address.to_lowercase();
    let mut hash = [0u8; 32];
    let hash = keccak256(lower_address_bytes.as_bytes());
    let hash_str = hex::encode(hash);

    for (i, c) in address.chars().enumerate() {
        let char_int =
            u8::from_str_radix(&hash_str.chars().nth(i).unwrap().to_string(), 16).unwrap();
        if (c.is_uppercase() && char_int <= 7) || (c.is_lowercase() && char_int > 7) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod test {
    use crate::address::EthAddress;
    use tcx_chain::Address;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, TypedPrivateKey};

    #[test]
    fn test_eth_address() {
        let private_key_bytes =
            hex::decode("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6")
                .unwrap();
        let mut secp256k1_privateKey =
            Secp256k1PrivateKey::from_slice(private_key_bytes.as_slice()).unwrap();
        secp256k1_privateKey.0.compressed = false;
        let typed_public_key = TypedPrivateKey::Secp256k1(secp256k1_privateKey).public_key();
        let coin_info = CoinInfo {
            coin: "ETHEREUM".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "testnet".to_string(),
            seg_wit: "".to_string(),
        };
        let address = EthAddress::from_public_key(&typed_public_key, &coin_info).unwrap();
        assert_eq!(
            address.to_string(),
            "0xef678007d18427e6022059dbc264f27507cd1ffc"
        );

        let is_valid =
            EthAddress::is_valid("0xef678007d18427e6022059dbc264f27507cd1ffc", &coin_info);
        assert_eq!(is_valid, true);

        assert_eq!(
            EthAddress::is_valid("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5", &coin_info),
            true
        );
        assert_eq!(
            EthAddress::is_valid("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfE5", &coin_info),
            false
        );
    }
}
