use crate::Result;
use keccak_hash::keccak;
use regex::Regex;
use tcx_chain::Address;
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;
pub struct EthAddress();

impl Address for EthAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<String> {
        let public_key_bytes = public_key.to_bytes();
        let address = EthAddress::get_address_from_pubkey(public_key_bytes.as_slice())?;
        Ok(address)
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        is_valid_address(address).expect("eth_address_check_error")
    }
}

pub fn is_valid_address(address: &str) -> Result<bool> {
    if address.is_empty() || address.len() != 42 || !address.starts_with("0x") {
        return Ok(false);
    }

    let ethAddrRegex = Regex::new(r"^(0x)?[0-9a-fA-F]{40}$").unwrap();
    if !ethAddrRegex.is_match(address.as_ref()) {
        return Ok(false);
    }

    let address_temp = &address[2..];
    let lower_address_bytes = address_temp.to_lowercase();
    let mut hash = [0u8; 32];
    keccak_hash::keccak_256(lower_address_bytes.as_bytes(), &mut hash);
    let hash_str = hex::encode(hash);

    for (i, c) in address_temp.chars().enumerate() {
        let char_int = u8::from_str_radix(&hash_str.chars().nth(i).unwrap().to_string(), 16)?;
        if (c.is_uppercase() && char_int <= 7) || (c.is_lowercase() && char_int > 7) {
            return Ok(false);
        }
    }
    Ok(true)
}

impl EthAddress {
    pub fn get_address_from_pubkey(public_key: &[u8]) -> Result<String> {
        let pubkey_hash = keccak::<&[u8]>(public_key[1..].as_ref());
        let addr_bytes = &pubkey_hash[12..];
        Ok(hex::encode(addr_bytes))
    }
}
