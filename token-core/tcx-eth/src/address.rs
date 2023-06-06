use crate::Result;
use keccak_hash::keccak;
use tcx_chain::Address;
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;
pub struct EthAddress();

impl Address for EthAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<String> {
        let public_key_bytes = public_key.to_bytes();
        let pubkey_hash = keccak(public_key_bytes[1..].as_ref());
        let addr_bytes = &pubkey_hash[12..];
        Ok(hex::encode(addr_bytes))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        todo!()
    }
}

impl EthAddress {
    pub fn get_address_from_pubkey(public_key: &[u8]) -> Result<String> {
        let pubkey_hash = keccak(public_key[1..].as_ref());
        let addr_bytes = &pubkey_hash[12..];
        Ok(hex::encode(addr_bytes))
    }
}
