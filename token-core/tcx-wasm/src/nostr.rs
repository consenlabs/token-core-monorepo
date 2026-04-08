use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{ecdh, KeyPair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::Sha256;
use tcx_common::FromHex;

pub const DEFAULT_PATH: &str = "m/44'/1237'/0'/0/0";
pub const SERVER_PUBKEY: &str = "d39eadac9f88ea1a77b034e8586191ed5435f44b01dea8f214f45fd7bd0b8e0f";

const NIP44_SALT: &[u8] = b"nip44-v2";
const NIP44_VERSION: u8 = 0x02;
const MIN_PLAINTEXT_SIZE: usize = 1;
const MAX_PLAINTEXT_SIZE: usize = 65535;

type HmacSha256 = Hmac<Sha256>;

struct MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

// --- Key derivation ---

pub fn derive_secret_key(mnemonic: &str, path: &str) -> Result<SecretKey, String> {
    let seed = tcx_keystore::mnemonic_to_seed(mnemonic).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    let master =
        ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_ref()).map_err(|e| e.to_string())?;
    let derivation: DerivationPath = path
        .parse()
        .map_err(|e: bitcoin::util::bip32::Error| e.to_string())?;
    let derived = master
        .derive_priv(&secp, &derivation)
        .map_err(|e| e.to_string())?;
    Ok(derived.private_key)
}

pub fn get_xonly_pubkey(secret_key: &SecretKey) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let keypair = KeyPair::from_seckey_slice(&secp, &secret_key[..]).expect("valid secret key");
    keypair.x_only_public_key().0
}

// --- Nostr event signing (NIP-01 + BIP340) ---

pub fn compute_event_id(
    pubkey_hex: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    use sha2::Digest;
    let serialized = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    let json_str = serde_json::to_string(&serialized).expect("valid JSON");
    let hash = Sha256::digest(json_str.as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn schnorr_sign(secret_key: &SecretKey, message: &[u8; 32]) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();
    let keypair = KeyPair::from_seckey_slice(&secp, &secret_key[..]).map_err(|e| e.to_string())?;
    let msg = Message::from_slice(message).map_err(|e| e.to_string())?;
    let mut aux_rand = [0u8; 32];
    getrandom::getrandom(&mut aux_rand).map_err(|e| e.to_string())?;
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
    Ok(sig[..].to_vec())
}

// --- NIP-44 v2 encryption ---

pub fn parse_pubkey(hex_str: &str) -> Result<PublicKey, String> {
    let bytes = Vec::from_hex(hex_str).map_err(|e| e.to_string())?;
    match bytes.len() {
        32 => {
            let xonly = XOnlyPublicKey::from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(PublicKey::from_x_only_public_key(
                xonly,
                secp256k1::Parity::Even,
            ))
        }
        33 | 65 => PublicKey::from_slice(&bytes).map_err(|e| e.to_string()),
        _ => Err("invalid public key length".to_string()),
    }
}

pub fn get_conversation_key(secret_key: &SecretKey, pubkey: &PublicKey) -> [u8; 32] {
    let shared_point = ecdh::shared_secret_point(pubkey, secret_key);
    let shared_x = &shared_point[..32];
    // HKDF-extract: PRK = HMAC-SHA256(salt, IKM)
    let mut mac = HmacSha256::new_from_slice(NIP44_SALT).expect("valid key size");
    mac.update(shared_x);
    let result = mac.finalize().into_bytes();
    let mut conv_key = [0u8; 32];
    conv_key.copy_from_slice(&result);
    conv_key
}

pub fn nip44_encrypt(conversation_key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let unpadded = plaintext.as_bytes();
    if unpadded.is_empty() || unpadded.len() > MAX_PLAINTEXT_SIZE {
        return Err("invalid plaintext length".to_string());
    }

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;

    let keys = get_message_keys(conversation_key, &nonce)?;
    let mut ciphertext = pad(unpadded)?;

    let mut cipher = ChaCha20::new_from_slices(&keys.chacha_key, &keys.chacha_nonce)
        .map_err(|e| e.to_string())?;
    cipher.apply_keystream(&mut ciphertext);

    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).expect("valid key size");
    mac.update(&nonce);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac_bytes);

    Ok(base64::encode(&payload))
}

pub fn nip44_decrypt(conversation_key: &[u8; 32], payload: &str) -> Result<String, String> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err("unknown encryption version".to_string());
    }
    if payload.len() < 132 || payload.len() > 87472 {
        return Err("invalid payload size".to_string());
    }

    let data = base64::decode(payload).map_err(|e| e.to_string())?;
    if data.len() < 99 || data.len() > 65603 {
        return Err("invalid data size".to_string());
    }

    let version = data[0];
    if version != NIP44_VERSION {
        return Err(format!("unknown version {}", version));
    }

    let nonce: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| "invalid nonce".to_string())?;
    let ciphertext = &data[33..data.len() - 32];
    let expected_mac = &data[data.len() - 32..];

    let keys = get_message_keys(conversation_key, &nonce)?;

    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).expect("valid key size");
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(expected_mac)
        .map_err(|_| "invalid MAC".to_string())?;

    let mut plaintext_padded = ciphertext.to_vec();
    let mut cipher = ChaCha20::new_from_slices(&keys.chacha_key, &keys.chacha_nonce)
        .map_err(|e| e.to_string())?;
    cipher.apply_keystream(&mut plaintext_padded);

    let plaintext = unpad(&plaintext_padded)?;
    String::from_utf8(plaintext).map_err(|e| e.to_string())
}

// --- Internal helpers ---

fn get_message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<MessageKeys, String> {
    let hkdf = Hkdf::<Sha256>::from_prk(conversation_key).map_err(|e| e.to_string())?;
    let mut keys = [0u8; 76];
    hkdf.expand(nonce, &mut keys).map_err(|e| e.to_string())?;

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&keys[0..32]);
    chacha_nonce.copy_from_slice(&keys[32..44]);
    hmac_key.copy_from_slice(&keys[44..76]);

    Ok(MessageKeys {
        chacha_key,
        chacha_nonce,
        hmac_key,
    })
}

fn calc_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }
    let x = unpadded_len - 1;
    let next_power = 1usize << (usize::BITS - x.leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (x / chunk + 1)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unpadded_len = plaintext.len();
    if !(MIN_PLAINTEXT_SIZE..=MAX_PLAINTEXT_SIZE).contains(&unpadded_len) {
        return Err("invalid plaintext length".to_string());
    }
    let padded_len = calc_padded_len(unpadded_len);
    let mut result = Vec::with_capacity(2 + padded_len);
    result.extend_from_slice(&(unpadded_len as u16).to_be_bytes());
    result.extend_from_slice(plaintext);
    result.resize(2 + padded_len, 0);
    Ok(result)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 2 {
        return Err("invalid padding".to_string());
    }
    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0
        || 2 + unpadded_len > padded.len()
        || padded.len() != 2 + calc_padded_len(unpadded_len)
    {
        return Err("invalid padding".to_string());
    }
    Ok(padded[2..2 + unpadded_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tcx_common::ToHex;

    #[test]
    fn test_calc_padded_len() {
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(16), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 64);
        assert_eq!(calc_padded_len(37), 64);
        assert_eq!(calc_padded_len(64), 64);
        assert_eq!(calc_padded_len(65), 96);
        assert_eq!(calc_padded_len(256), 256);
        assert_eq!(calc_padded_len(257), 320);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let cases = [b"a".as_ref(), b"hello world", &[0x42; 100], &[0xff; 32]];
        for plaintext in cases {
            let padded = pad(plaintext).unwrap();
            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, plaintext);
        }
    }

    #[test]
    fn test_get_conversation_key_vector() {
        let secp = Secp256k1::new();
        let sec1 = SecretKey::from_slice(
            &Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let sec2 = SecretKey::from_slice(
            &Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
        )
        .unwrap();
        let pub2 = PublicKey::from_secret_key(&secp, &sec2);

        let conv_key = get_conversation_key(&sec1, &pub2);
        assert_eq!(
            conv_key.to_hex(),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
    }

    #[test]
    fn test_nip44_encrypt_decrypt_roundtrip() {
        let secp = Secp256k1::new();
        let sec1 = SecretKey::from_slice(
            &Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let sec2 = SecretKey::from_slice(
            &Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
        )
        .unwrap();
        let pub2 = PublicKey::from_secret_key(&secp, &sec2);
        let pub1 = PublicKey::from_secret_key(&secp, &sec1);

        let conv_key_1 = get_conversation_key(&sec1, &pub2);
        let conv_key_2 = get_conversation_key(&sec2, &pub1);
        assert_eq!(conv_key_1, conv_key_2);

        let plaintext = "hello nostr";
        let encrypted = nip44_encrypt(&conv_key_1, plaintext).unwrap();
        let decrypted = nip44_decrypt(&conv_key_2, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
