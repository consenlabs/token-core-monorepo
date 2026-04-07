use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use wasm_bindgen::prelude::*;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn aes_cbc_encrypt_inner(
    key_hex: &str,
    iv_hex: &str,
    plaintext_hex: &str,
) -> Result<String, String> {
    let key = hex::decode(key_hex).map_err(|e| format!("invalid key hex: {e}"))?;
    let iv = hex::decode(iv_hex).map_err(|e| format!("invalid iv hex: {e}"))?;
    let data = hex::decode(plaintext_hex).map_err(|e| format!("invalid plaintext hex: {e}"))?;

    if key.len() != 32 {
        return Err("key must be 32 bytes (64 hex chars) for AES-256".into());
    }
    if iv.len() != 16 {
        return Err("iv must be 16 bytes (32 hex chars)".into());
    }

    let padding_len = 16 - (data.len() % 16);
    let mut buf = vec![0u8; data.len() + padding_len];
    let ct = Aes256CbcEnc::new(key.as_slice().into(), iv.as_slice().into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buf)
        .map_err(|_| "encryption failed")?;

    Ok(hex::encode(ct))
}

pub fn aes_cbc_decrypt_inner(
    key_hex: &str,
    iv_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, String> {
    let key = hex::decode(key_hex).map_err(|e| format!("invalid key hex: {e}"))?;
    let iv = hex::decode(iv_hex).map_err(|e| format!("invalid iv hex: {e}"))?;
    let encrypted = hex::decode(ciphertext_hex).map_err(|e| format!("invalid ciphertext hex: {e}"))?;

    if key.len() != 32 {
        return Err("key must be 32 bytes (64 hex chars) for AES-256".into());
    }
    if iv.len() != 16 {
        return Err("iv must be 16 bytes (32 hex chars)".into());
    }
    if encrypted.is_empty() || encrypted.len() % 16 != 0 {
        return Err("ciphertext length must be a non-zero multiple of 16 bytes".into());
    }

    let mut buf = vec![0u8; encrypted.len()];
    let pt = Aes256CbcDec::new(key.as_slice().into(), iv.as_slice().into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&encrypted, &mut buf)
        .map_err(|_| "decryption failed: invalid padding or wrong key/iv".to_string())?;

    Ok(hex::encode(pt))
}

/// AES-256-CBC encrypt with PKCS7 padding.
///
/// - `key_hex`: 32-byte key (64 hex chars), e.g. from FIDO PRF
/// - `iv_hex`: 16-byte IV (32 hex chars)
/// - `plaintext_hex`: data to encrypt (hex encoded)
///
/// Returns ciphertext as hex string.
#[wasm_bindgen]
pub fn aes_cbc_encrypt(
    key_hex: &str,
    iv_hex: &str,
    plaintext_hex: &str,
) -> Result<String, JsError> {
    aes_cbc_encrypt_inner(key_hex, iv_hex, plaintext_hex).map_err(|e| JsError::new(&e))
}

/// AES-256-CBC decrypt with PKCS7 padding.
///
/// - `key_hex`: 32-byte key (64 hex chars)
/// - `iv_hex`: 16-byte IV (32 hex chars)
/// - `ciphertext_hex`: data to decrypt (hex encoded)
///
/// Returns plaintext as hex string.
#[wasm_bindgen]
pub fn aes_cbc_decrypt(
    key_hex: &str,
    iv_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, JsError> {
    aes_cbc_decrypt_inner(key_hex, iv_hex, ciphertext_hex).map_err(|e| JsError::new(&e))
}
