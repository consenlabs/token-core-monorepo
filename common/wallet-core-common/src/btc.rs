use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1;
use bitcoin::{PubkeyHash, PublicKey, ScriptBuf, ScriptHash, WitnessVersion};
use std::error::Error;
use std::fmt;

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

pub fn p2pkh_hash(pub_key: &[u8]) -> Result<PubkeyHash, AddressError> {
    let pub_key =
        PublicKey::from_slice(pub_key).map_err(|err| AddressError::new(err.to_string()))?;
    Ok(pub_key.pubkey_hash())
}

/// Derives a P2PKH hash from the compressed SEC serialization of a public key.
///
/// Both compressed and uncompressed public key inputs produce the same hash.
pub fn compressed_p2pkh_hash(pub_key: &[u8]) -> Result<PubkeyHash, AddressError> {
    let pub_key = compressed_public_key(pub_key)?;
    Ok(pub_key.pubkey_hash())
}

pub fn p2shwpkh_hash(pub_key: &[u8]) -> Result<ScriptHash, AddressError> {
    let pub_key = compressed_public_key(pub_key)?;
    let script = ScriptBuf::new_p2wpkh(
        &pub_key
            .wpubkey_hash()
            .map_err(|err| AddressError::new(err.to_string()))?,
    );
    Ok(script.script_hash())
}

pub fn p2wpkh_program(pub_key: &[u8]) -> Result<Vec<u8>, AddressError> {
    let pub_key = compressed_public_key(pub_key)?;
    Ok(pub_key
        .wpubkey_hash()
        .map_err(|err| AddressError::new(err.to_string()))?
        .as_byte_array()
        .to_vec())
}

pub fn p2tr_program(pub_key: &[u8]) -> Result<Vec<u8>, AddressError> {
    let pub_key = secp256k1::PublicKey::from_slice(pub_key)
        .map_err(|err| AddressError::new(err.to_string()))?;
    let (x_only, _) = pub_key.x_only_public_key();
    let pub_key = UntweakedPublicKey::from(x_only);
    let secp = secp256k1::Secp256k1::new();
    let output_key = pub_key.tap_tweak(&secp, None).0;
    Ok(output_key.serialize().to_vec())
}

pub fn p2pkh_script_pubkey(hash: &PubkeyHash) -> ScriptBuf {
    ScriptBuf::new_p2pkh(hash)
}

pub fn p2sh_script_pubkey(hash: &ScriptHash) -> ScriptBuf {
    ScriptBuf::new_p2sh(hash)
}

pub fn witness_script_pubkey(version: WitnessVersion, program: &[u8]) -> ScriptBuf {
    let witness_program =
        bitcoin::WitnessProgram::new(version, program).expect("valid witness program");
    ScriptBuf::new_witness_program(&witness_program)
}

fn compressed_public_key(pub_key: &[u8]) -> Result<PublicKey, AddressError> {
    let mut pub_key =
        PublicKey::from_slice(pub_key).map_err(|err| AddressError::new(err.to_string()))?;
    pub_key.compressed = true;
    Ok(pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_common_btc_payloads_from_public_key() {
        let pubkey =
            hex::decode("02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba")
                .unwrap();

        assert_eq!(
            hex::encode(p2pkh_hash(&pubkey).unwrap().as_byte_array()),
            "e6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
        assert_eq!(
            hex::encode(p2shwpkh_hash(&pubkey).unwrap().as_byte_array()),
            "bc64b2d79807cd3d72101c3298b89117d32097fb"
        );
        assert_eq!(
            hex::encode(p2wpkh_program(&pubkey).unwrap()),
            "e6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
    }

    #[test]
    fn p2pkh_preserves_uncompressed_public_key_serialization() {
        let compressed =
            hex::decode("02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba")
                .unwrap();
        let uncompressed = secp256k1::PublicKey::from_slice(&compressed)
            .unwrap()
            .serialize_uncompressed();

        assert_eq!(
            p2pkh_hash(&uncompressed).unwrap(),
            PubkeyHash::hash(&uncompressed)
        );
        assert_ne!(
            p2pkh_hash(&uncompressed).unwrap(),
            p2pkh_hash(&compressed).unwrap()
        );
        assert_eq!(
            compressed_p2pkh_hash(&uncompressed).unwrap(),
            compressed_p2pkh_hash(&compressed).unwrap()
        );

        // SegWit only permits compressed public keys, so its helpers keep
        // normalizing a valid uncompressed SEC key to compressed form.
        assert_eq!(
            p2wpkh_program(&uncompressed).unwrap(),
            p2wpkh_program(&compressed).unwrap()
        );
    }

    #[test]
    fn builds_script_pubkeys_from_payloads() {
        let pubkey_hash = PubkeyHash::from_byte_array(
            hex::decode("ca4d8acded69ce4f05d0925946d261f86c675fd8")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            hex::encode(p2pkh_script_pubkey(&pubkey_hash).as_bytes()),
            "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac"
        );

        let script_hash = ScriptHash::from_byte_array(
            hex::decode("bc64b2d79807cd3d72101c3298b89117d32097fb")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            hex::encode(p2sh_script_pubkey(&script_hash).as_bytes()),
            "a914bc64b2d79807cd3d72101c3298b89117d32097fb87"
        );

        let program = hex::decode("e6cfaab9a59ba187f0a45db0b169c21bb48f09b3").unwrap();
        assert_eq!(
            hex::encode(witness_script_pubkey(WitnessVersion::V0, &program).as_bytes()),
            "0014e6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
    }
}
