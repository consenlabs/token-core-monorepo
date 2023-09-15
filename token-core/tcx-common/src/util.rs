use crate::Result;
use keccak_hash::keccak;

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let ret_data;
    if value.starts_with("0x") {
        ret_data = hex::decode(&value[2..value.len()])?
    } else {
        ret_data = hex::decode(value)?
    }

    Ok(ret_data)
}

pub fn utf8_or_hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    if value.starts_with("0x") {
        hex_to_bytes(value)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

// TODO: relace with EthAddress::from_slice
pub fn get_address_from_pubkey(public_key: &[u8]) -> Result<String> {
    let pubkey_hash = keccak::<&[u8]>(public_key[1..].as_ref());
    let addr_bytes = &pubkey_hash[12..];
    Ok(hex::encode(addr_bytes))
}
