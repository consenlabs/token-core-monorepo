use bech32::{Bech32, Hrp};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::PublicKey;
use std::error::Error;
use std::fmt;

const ADDRESS_LENGTH: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressError(String);

impl AddressError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for AddressError {}

pub fn address_from_pubkey(hrp: &str, pubkey: &[u8]) -> Result<String, AddressError> {
    let public_key = PublicKey::from_slice(pubkey)
        .map_err(|err| AddressError::new(err.to_string()))?
        .serialize();
    let pubkey_hash = hash160::Hash::hash(&public_key);
    let hrp = Hrp::parse(hrp).map_err(|err| AddressError::new(err.to_string()))?;
    bech32::encode::<Bech32>(hrp, pubkey_hash.as_byte_array())
        .map_err(|err| AddressError::new(err.to_string()))
}

pub fn is_valid_address(address: &str) -> bool {
    match bech32::decode(address) {
        Ok((_hrp, data)) => data.len() == ADDRESS_LENGTH,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_cosmos_address_from_public_key() {
        let pubkey =
            hex::decode("037a525043e79a9051d58214a9a2a70b657b3d49124dcd0acc4730df5f35d74b32")
                .unwrap();
        assert_eq!(
            address_from_pubkey("cosmos", &pubkey).unwrap(),
            "cosmos1pt9904aqg739q6p9kgc2v0puqvj6atp0zsj70g"
        );

        let pubkey =
            hex::decode("0317f65e6736ad182b47e386af40af0f26fb524bdd94e172a6145a6603d65a44b2")
                .unwrap();
        assert_eq!(
            address_from_pubkey("osmo", &pubkey).unwrap(),
            "osmo1m566v5rcklnac8vc0dftfu4lnvznhlu79269e8"
        );
    }

    #[test]
    fn validates_bech32_address_length() {
        assert!(is_valid_address(
            "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl"
        ));
        assert!(!is_valid_address(
            "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhll"
        ));
        assert!(!is_valid_address(
            "ckt1qyqd5eyygtdmwdr7ge736zw6z0ju6wsw7rssu8fcve"
        ));
    }
}
