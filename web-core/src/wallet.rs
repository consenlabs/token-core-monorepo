use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ── Seed Generation ─────────────────────────────────────────────────────────

pub fn generate_mnemonic_inner(word_count: u32) -> Result<String, String> {
    let mnemonic_type = match word_count {
        12 => MnemonicType::Words12,
        24 => MnemonicType::Words24,
        _ => return Err("only 12 or 24 word counts are supported".into()),
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
    Ok(mnemonic.to_string())
}

#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32) -> Result<String, JsError> {
    generate_mnemonic_inner(word_count).map_err(|e| JsError::new(&e))
}

pub fn mnemonic_to_seed_inner(mnemonic: &str, passphrase: &str) -> Result<String, String> {
    let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English).map_err(map_err)?;
    let seed = Seed::new(&mnemonic, passphrase);
    Ok(hex::encode(seed.as_bytes()))
}

#[wasm_bindgen]
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<String, JsError> {
    mnemonic_to_seed_inner(mnemonic, passphrase).map_err(|e| JsError::new(&e))
}

// ── BIP44 Key Derivation ────────────────────────────────────────────────────

pub fn derive_key_inner(seed_hex: &str, path: &str) -> Result<(String, String), String> {
    let seed_bytes = hex::decode(seed_hex).map_err(map_err)?;
    if seed_bytes.len() != 64 {
        return Err("seed must be 64 bytes (128 hex chars)".into());
    }

    let derivation_path = DerivationPath::from_str(path).map_err(map_err)?;
    let child_xprv =
        XPrv::derive_from_path(&seed_bytes, &derivation_path).map_err(map_err)?;

    let private_key_hex = hex::encode(child_xprv.to_bytes());
    let public_key_hex = hex::encode(child_xprv.public_key().to_bytes());
    Ok((private_key_hex, public_key_hex))
}

#[wasm_bindgen]
pub fn derive_key(seed_hex: &str, path: &str) -> Result<JsValue, JsError> {
    let (private_key_hex, public_key_hex) =
        derive_key_inner(seed_hex, path).map_err(|e| JsError::new(&e))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"private_key".into(), &private_key_hex.into())
        .map_err(|_| JsError::new("failed to set private_key"))?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_key_hex.into())
        .map_err(|_| JsError::new("failed to set public_key"))?;
    Ok(obj.into())
}

pub fn derive_public_key_inner(seed_hex: &str, path: &str) -> Result<String, String> {
    let (_, public_key_hex) = derive_key_inner(seed_hex, path)?;
    Ok(public_key_hex)
}

#[wasm_bindgen]
pub fn derive_public_key(seed_hex: &str, path: &str) -> Result<String, JsError> {
    derive_public_key_inner(seed_hex, path).map_err(|e| JsError::new(&e))
}

// ── secp256k1 Signing ───────────────────────────────────────────────────────

pub fn secp256k1_sign_inner(
    private_key_hex: &str,
    message_hash_hex: &str,
) -> Result<(String, String, u8), String> {
    let pk_bytes = hex::decode(private_key_hex).map_err(map_err)?;
    let hash_bytes = hex::decode(message_hash_hex).map_err(map_err)?;
    if hash_bytes.len() != 32 {
        return Err("message_hash must be 32 bytes (64 hex chars)".into());
    }

    let signing_key =
        SigningKey::from_bytes(pk_bytes.as_slice().into()).map_err(map_err)?;

    let (signature, recid) = signing_key
        .sign_prehash_recoverable(&hash_bytes)
        .map_err(map_err)?;

    let sig_bytes = signature.to_bytes();
    let r_hex = hex::encode(&sig_bytes[..32]);
    let s_hex = hex::encode(&sig_bytes[32..]);
    Ok((r_hex, s_hex, recid.to_byte()))
}

#[wasm_bindgen]
pub fn secp256k1_sign(private_key_hex: &str, message_hash_hex: &str) -> Result<JsValue, JsError> {
    let (r_hex, s_hex, v) =
        secp256k1_sign_inner(private_key_hex, message_hash_hex).map_err(|e| JsError::new(&e))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"r".into(), &r_hex.into())
        .map_err(|_| JsError::new("failed to set r"))?;
    js_sys::Reflect::set(&obj, &"s".into(), &s_hex.into())
        .map_err(|_| JsError::new("failed to set s"))?;
    js_sys::Reflect::set(&obj, &"v".into(), &JsValue::from(v))
        .map_err(|_| JsError::new("failed to set v"))?;
    Ok(obj.into())
}

pub fn secp256k1_verify_inner(
    public_key_hex: &str,
    message_hash_hex: &str,
    signature_hex: &str,
) -> Result<bool, String> {
    let pk_bytes = hex::decode(public_key_hex).map_err(map_err)?;
    let hash_bytes = hex::decode(message_hash_hex).map_err(map_err)?;
    let sig_bytes = hex::decode(signature_hex).map_err(map_err)?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(map_err)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(map_err)?;

    Ok(verifying_key.verify_prehash(&hash_bytes, &signature).is_ok())
}

#[wasm_bindgen]
pub fn secp256k1_verify(
    public_key_hex: &str,
    message_hash_hex: &str,
    signature_hex: &str,
) -> Result<bool, JsError> {
    secp256k1_verify_inner(public_key_hex, message_hash_hex, signature_hex)
        .map_err(|e| JsError::new(&e))
}
