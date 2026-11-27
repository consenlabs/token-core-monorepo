//! Versioned authenticated encryption. HKDF and AAD separate every purpose.
use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

pub const PREFIX: &str = "tcx-aead-v1:";
const SALT: &[u8] = b"token-core/authenticated-encryption/v1";

pub fn derive_key(secret: &[u8], purpose: &[u8]) -> Result<[u8; 32]> {
    ensure!(secret.len() >= 16, "invalid_key_iv_length");
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(SALT), secret)
        .expand(purpose, &mut key)
        .map_err(|_| anyhow!("invalid_key_iv_length"))?;
    Ok(key)
}

pub fn seal(secret: &[u8], purpose: &[u8], plaintext: &[u8]) -> Result<String> {
    let key = derive_key(secret, purpose)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid_key_iv_length"))?;
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow!("random_source_unavailable"))?;
    let nonce: XNonce = nonce.into();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: purpose,
            },
        )
        .map_err(|_| anyhow!("invalid_ciphertext"))?;
    Ok(format!(
        "{}{}",
        PREFIX,
        hex::encode([&nonce[..], &ciphertext].concat())
    ))
}

pub fn open(secret: &[u8], purpose: &[u8], envelope: &str) -> Result<Vec<u8>> {
    let encoded = envelope
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("invalid_ciphertext"))?;
    let payload = hex::decode(encoded).map_err(|_| anyhow!("invalid_ciphertext"))?;
    ensure!(payload.len() >= 24 + 16, "invalid_ciphertext");
    let key = derive_key(secret, purpose)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid_key_iv_length"))?;
    let nonce: XNonce = <[u8; 24]>::try_from(&payload[..24])
        .map_err(|_| anyhow!("invalid_ciphertext"))?
        .into();
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &payload[24..],
                aad: purpose,
            },
        )
        .map_err(|_| anyhow!("invalid_ciphertext"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn randomized_authenticated_envelopes() {
        let key = [7; 32];
        let a = seal(&key, b"backup", b"secret").unwrap();
        let b = seal(&key, b"backup", b"secret").unwrap();
        assert_ne!(a, b);
        assert_eq!(open(&key, b"backup", &a).unwrap(), b"secret");
        assert!(open(&[8; 32], b"backup", &a).is_err());
        assert!(open(&key, b"xpub", &a).is_err());
        for len in 0..a.len() {
            assert!(open(&key, b"backup", &a[..len]).is_err());
        }
        let mut corrupt = a.into_bytes();
        let last = corrupt.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(open(&key, b"backup", std::str::from_utf8(&corrupt).unwrap()).is_err());
    }
}
