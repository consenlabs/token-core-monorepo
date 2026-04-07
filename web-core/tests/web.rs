use wasm_bindgen_test::*;
use web_core::crypto::*;
use web_core::wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

// ── Seed Generation Tests ───────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_generate_mnemonic_12_words() {
    let phrase = generate_mnemonic_inner(12).unwrap();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 12);
}

#[wasm_bindgen_test]
fn test_generate_mnemonic_24_words() {
    let phrase = generate_mnemonic_inner(24).unwrap();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
}

#[wasm_bindgen_test]
fn test_generate_mnemonic_invalid_count() {
    assert!(generate_mnemonic_inner(15).is_err());
}

#[wasm_bindgen_test]
fn test_mnemonic_to_seed_bip39_vector() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    assert_eq!(seed_hex.len(), 128);
    assert_eq!(
        seed_hex,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );
}

#[wasm_bindgen_test]
fn test_mnemonic_to_seed_with_passphrase() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_no_pass = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let seed_with_pass = mnemonic_to_seed_inner(mnemonic, "my_passphrase").unwrap();
    assert_ne!(seed_no_pass, seed_with_pass);
}

#[wasm_bindgen_test]
fn test_mnemonic_to_seed_invalid() {
    assert!(mnemonic_to_seed_inner("invalid words here", "").is_err());
}

// ── BIP44 Derivation Tests ──────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_derive_key_eth_path() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (priv_key, pub_key) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();

    assert_eq!(pub_key.len(), 66, "compressed pubkey = 33 bytes");
    assert!(pub_key.starts_with("02") || pub_key.starts_with("03"));
    assert_eq!(priv_key.len(), 64, "private key = 32 bytes");
}

#[wasm_bindgen_test]
fn test_derive_key_btc_path() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (_priv_key, pub_key) = derive_key_inner(&seed_hex, "m/44'/0'/0'/0/0").unwrap();

    assert_eq!(pub_key.len(), 66);
    assert!(pub_key.starts_with("02") || pub_key.starts_with("03"));
}

#[wasm_bindgen_test]
fn test_derive_public_key_matches() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();

    let (_priv, pub_from_derive) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();
    let pub_only = derive_public_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();
    assert_eq!(pub_from_derive, pub_only);
}

#[wasm_bindgen_test]
fn test_derive_key_invalid_path() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    assert!(derive_key_inner(&seed_hex, "invalid_path").is_err());
}

#[wasm_bindgen_test]
fn test_derive_key_invalid_seed() {
    assert!(derive_key_inner("abcd", "m/44'/60'/0'/0/0").is_err());
}

// ── secp256k1 Signing Tests ─────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_secp256k1_sign_and_verify() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (priv_key, pub_key) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();

    let msg_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let (r, s, v) = secp256k1_sign_inner(&priv_key, msg_hash).unwrap();

    assert_eq!(r.len(), 64);
    assert_eq!(s.len(), 64);
    assert!(v <= 1);

    let sig_hex = format!("{}{}", r, s);
    let verified = secp256k1_verify_inner(&pub_key, msg_hash, &sig_hex).unwrap();
    assert!(verified);
}

#[wasm_bindgen_test]
fn test_secp256k1_sign_low_s() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (priv_key, _) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();

    let msg_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let (_r, s, _v) = secp256k1_sign_inner(&priv_key, msg_hash).unwrap();

    let half_order = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
    assert!(s.as_str() <= half_order, "s should be in low-S form (BIP-62)");
}

#[wasm_bindgen_test]
fn test_secp256k1_verify_invalid_signature() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (_, pub_key) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();

    let msg_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let bad_sig = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001";
    let verified = secp256k1_verify_inner(&pub_key, msg_hash, bad_sig).unwrap();
    assert!(!verified);
}

#[wasm_bindgen_test]
fn test_secp256k1_sign_invalid_private_key() {
    let bad_pk = "0000000000000000000000000000000000000000000000000000000000000000";
    let msg_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    assert!(secp256k1_sign_inner(bad_pk, msg_hash).is_err());
}

#[wasm_bindgen_test]
fn test_secp256k1_sign_invalid_hash_length() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (priv_key, _) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();
    assert!(secp256k1_sign_inner(&priv_key, "abcd").is_err());
}

#[wasm_bindgen_test]
fn test_secp256k1_sign_recoverable() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed_hex = mnemonic_to_seed_inner(mnemonic, "").unwrap();
    let (priv_key, pub_key) = derive_key_inner(&seed_hex, "m/44'/60'/0'/0/0").unwrap();

    let msg_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let (r, s, v) = secp256k1_sign_inner(&priv_key, msg_hash).unwrap();

    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let sig_bytes = hex::decode(format!("{}{}", r, s)).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    let recid = RecoveryId::from_byte(v).unwrap();
    let hash_bytes = hex::decode(msg_hash).unwrap();

    let recovered = VerifyingKey::recover_from_prehash(&hash_bytes, &sig, recid).unwrap();
    let recovered_hex = hex::encode(recovered.to_sec1_bytes());
    assert_eq!(recovered_hex, pub_key);
}

// ── AES-256-CBC Tests ───────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_aes_cbc_encrypt_decrypt_roundtrip() {
    let key = "0102030401020304010203040102030401020304010203040102030401020304";
    let iv = "01020304010203040102030401020304";
    let plaintext = hex::encode(b"hello web-core AES-256-CBC!");

    let ct = aes_cbc_encrypt_inner(key, iv, &plaintext).unwrap();
    let pt = aes_cbc_decrypt_inner(key, iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[wasm_bindgen_test]
fn test_aes_cbc_known_vector() {
    let key = "0102030401020304010203040102030401020304010203040102030401020304";
    let iv = "01020304010203040102030401020304";
    let plaintext = hex::encode(b"TokenCoreX");

    let ct = aes_cbc_encrypt_inner(key, iv, &plaintext).unwrap();
    let pt = aes_cbc_decrypt_inner(key, iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[wasm_bindgen_test]
fn test_aes_cbc_invalid_key_length() {
    let short_key = "01020304";
    let iv = "01020304010203040102030401020304";
    assert!(aes_cbc_encrypt_inner(short_key, iv, "abcd").is_err());
}

#[wasm_bindgen_test]
fn test_aes_cbc_invalid_iv_length() {
    let key = "0102030401020304010203040102030401020304010203040102030401020304";
    let short_iv = "01020304";
    assert!(aes_cbc_encrypt_inner(key, short_iv, "abcd").is_err());
}

#[wasm_bindgen_test]
fn test_aes_cbc_decrypt_wrong_key() {
    let key1 = "0102030401020304010203040102030401020304010203040102030401020304";
    let key2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let iv = "01020304010203040102030401020304";
    let pt = hex::encode(b"secret data");

    let ct = aes_cbc_encrypt_inner(key1, iv, &pt).unwrap();
    assert!(aes_cbc_decrypt_inner(key2, iv, &ct).is_err());
}
