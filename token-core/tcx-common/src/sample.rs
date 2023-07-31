use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use bip39::{Language, Mnemonic};
use bitcoin::secp256k1::Secp256k1 as BitcoinSecp256k1;
use bitcoin::util::base58;
use bitcoin::{
    util::bip32::{ChildNumber, Error, ExtendedPrivKey, ExtendedPubKey},
    Network,
};
use hmac_sha256;
use secp256k1::{ecdsa::Signature, KeyPair, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

//sha256
fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

//hmacsha256
fn hmacsha256(data: &[u8], key: &[u8]) -> Vec<u8> {
    // let hmac_hash = hmac_sha256::HMAC::mac(data, key).into_bytes().to_vec();
    let mut mac = hmac_sha256::HMAC::new(key);
    mac.update(data);
    mac.finalize().to_vec()
}

//secp256k1 sign
fn secp256k1_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let message = Message::from_slice(message).expect("32 bytes");
    let secret_key = SecretKey::from_slice(key).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let sig = secp.sign_ecdsa(&message, &secret_key);
    sig.serialize_compact()[..].to_vec()
}

//secp256k1 verify
fn secp256k1_verify(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_slice(message).expect("32 bytes");
    let public_key = PublicKey::from_slice(pubkey).expect("33 or 65 bytes, serialized according to the format specified by the `Compressed` or `Uncompressed` enum");
    let signature = Signature::from_compact(sig).expect("64 bytes, in compact format");
    secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
}

//bip32
fn bip44(mnemonic: &str, path: &str) -> String {
    // let bip32_deterministic_private_key =
    //         Bip32DeterministicPrivateKey::from_mnemonic(mnemonic).unwrap();
    // let bip32_deterministic_private_key = bip32_deterministic_private_key.derive(path).unwrap();
    // let private_key = bip32_deterministic_private_key.private_key().0;
    // let secp = BitcoinSecp256k1::new();
    // let public_key = private_key.public_key(&secp);
    // println!("{}", public_key.to_string());

    let mn = Mnemonic::from_phrase(mnemonic, Language::English).unwrap();
    let seed = bip39::Seed::new(&mn, "");
    let epk = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_ref()).unwrap();

    let secp256k1 = BitcoinSecp256k1::new();
    let mut parts = path.split('/').peekable();
    if *parts.peek().unwrap() == "m" {
        parts.next();
    }
    let children_nums = parts
        .map(str::parse)
        .collect::<std::result::Result<Vec<ChildNumber>, Error>>()
        .unwrap();
    let child_priv_key = epk.derive_priv(&secp256k1, &children_nums).unwrap();
    let child_pub_key = ExtendedPubKey::from_priv(&secp256k1, &child_priv_key);
    let encode_data = child_pub_key.encode();
    base58::check_encode_slice(&encode_data[..])
}

//Schnorr sign
fn schnorr_sign(key: &[u8], message: &[u8], aux_rand: Option<&[u8]>) -> String {
    let secp = Secp256k1::new();
    let message = Message::from_slice(message).expect("32 bytes");
    let _secret_key = SecretKey::from_slice(key).expect("32 bytes, within curve order");
    let keypair = KeyPair::from_seckey_slice(&secp, key).expect("32 bytes, within curve order");
    let singature = if aux_rand.is_some() {
        let mut temp_aux_rand: [u8; 32] = [0x00; 32];
        temp_aux_rand.copy_from_slice(aux_rand.unwrap());
        secp.sign_schnorr_with_aux_rand(&message, &keypair, &temp_aux_rand)
    } else {
        secp.sign_schnorr_no_aux_rand(&message, &keypair)
    };
    singature.to_string()
}

//Schnorr verify
fn schnorr_verify(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_slice(message).expect("32 bytes");
    let public_key = PublicKey::from_slice(pubkey).expect("33 or 65 bytes, serialized according to the format specified by the `Compressed` or `Uncompressed` enum");
    let x_only_public_key = public_key.x_only_public_key().0;
    let signature =
        secp256k1::schnorr::Signature::from_slice(sig).expect("64 bytes, in compact format");
    secp.verify_schnorr(&signature, &message, &x_only_public_key)
        .is_ok()
}

//aes-128-ctr encrypt no padding
fn aes_128_ctr_encrypt_no_padding(key: &[u8], plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
    type Aes128Ctr64LE = ctr::Ctr64BE<aes::Aes128>;
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes128Ctr64LE::new(key.into(), iv.into());
    cipher.apply_keystream(&mut buf);
    println!("{}", hex::encode(buf.clone()));
    buf
}

//aes-128-ctr decrypt no padding
fn aes_128_ctr_decrypt_no_padding(key: &[u8], ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    type Aes128Ctr64LE = ctr::Ctr64BE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new(key.into(), iv.into());
    let mut plaintext = [0u8; 34];
    // cipher.seek(0u32);
    cipher
        .apply_keystream_b2b(ciphertext, &mut plaintext)
        .unwrap();
    plaintext.to_vec()
}

#[cfg(test)]
mod test {

    use crate::{
        sample::{
            aes_128_ctr_decrypt_no_padding, hmacsha256, schnorr_sign, schnorr_verify, sha256,
        },
        util::hex_to_bytes,
    };

    use super::{aes_128_ctr_encrypt_no_padding, bip44, secp256k1_sign, secp256k1_verify};

    #[test]
    fn test_sha256() {
        let data =
            hex_to_bytes("0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1")
                .unwrap();
        let hash = sha256(data.as_slice());
        assert_eq!(
            hex::encode(hash),
            "58bbda5e10bc11a32d808e40f9da2161a64f00b5557762a161626afe19137445"
        );
    }

    #[test]
    fn test_hmacsha256() {
        let data =
            hex_to_bytes("0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1")
                .unwrap();
        let key =
            hex_to_bytes("0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1")
                .unwrap();
        let hash = hmacsha256(data.as_slice(), key.as_slice());
        assert_eq!(
            hex::encode(hash),
            "43b51a934c557eabc42d1225acbf5983f2d27dbc0828c191cbc7b13aee379ae5"
        );
    }

    #[test]
    fn test_secp256k1() {
        let private_key = "f28f5e654dbe8ad421b4a7cf8f060f35e5623feb62764155d5361e40b59f3303";
        let public_key = "0432c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d658aede012f4a4b2e3a893b71a787617feb04f19d2e3bac5cee989aa55e8057458";
        let key = hex_to_bytes(private_key).unwrap();
        let message =
            hex_to_bytes("98554559492cba57861c43c78b2de4902186366449fff702b734f71c78429624")
                .unwrap();
        let result = secp256k1_sign(key.as_slice(), message.as_slice());
        assert_eq!(hex::encode(result.clone()), "df9e5f590d347588ad0198faf849a70206045f583b42d52b5ff91022a09bbf4e530b3d1d7ec59c3205d6567af597f23686b8e342488b44ca1e46b9a7a93d8264");
        let result = secp256k1_verify(
            hex_to_bytes(public_key).unwrap().as_slice(),
            message.as_slice(),
            result.as_slice(),
        );
        assert_eq!(result, true);
    }

    #[test]
    fn test_schnorr() {
        let private_key = "f28f5e654dbe8ad421b4a7cf8f060f35e5623feb62764155d5361e40b59f3303";
        let public_key = "0432c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d658aede012f4a4b2e3a893b71a787617feb04f19d2e3bac5cee989aa55e8057458";
        let key = hex_to_bytes(private_key).unwrap();
        let message =
            hex_to_bytes("98554559492cba57861c43c78b2de4902186366449fff702b734f71c78429624")
                .unwrap();
        let signature = schnorr_sign(key.as_slice(), message.as_slice(), None);
        assert_eq!(signature, "0b000a4224b694869842c2fb3a8243cb90c1e6dd7a94b60c0184e0ddee709920645a6f8e7fc0da6fe09e97d93e9f776e5f42111b57189242870b61cbcb8114c7");
        let verify_result = schnorr_verify(
            hex_to_bytes(public_key).unwrap().as_slice(),
            message.as_slice(),
            hex_to_bytes(&signature).unwrap().as_slice(),
        );
        assert!(verify_result);
        let aux_rand: [u8; 32] = [0x01; 32];
        let signature = schnorr_sign(key.as_slice(), message.as_slice(), Some(aux_rand.as_ref()));
        assert_eq!(signature, "208947988926904e79d7107a57f1ab06582c78685561de0c912522db016049570e5663fc420b25286b70261ea1a98d3e60edb01466b7c992cd88f02512817454");
        let verify_result = schnorr_verify(
            hex_to_bytes(public_key).unwrap().as_slice(),
            message.as_slice(),
            hex_to_bytes(&signature).unwrap().as_slice(),
        );
        assert!(verify_result);
    }

    #[test]
    fn test_bip44() {
        let mnemonic = "inject kidney empty canal shadow pact comfort wife crush horse wife sketch";
        let path = "m/44'/0'/0'/0/0";
        let xpub = bip44(mnemonic, path);
        assert_eq!(xpub, "xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX");
    }

    #[test]
    fn test_aes_128_ctr() {
        let key = [0x42; 16];
        let iv = [0x24; 16];
        let plaintext = *b"hello world! this is my plaintext.";
        let ciphertext =
            hex::decode("3357121ebb5a29468bd861467596ce3d046163d218d0bae9a9d5532a8d4e19f5bf9a")
                .unwrap();

        let result = aes_128_ctr_encrypt_no_padding(&key, &plaintext[..], &iv);
        assert_eq!(result, ciphertext);
        let result = aes_128_ctr_decrypt_no_padding(&key, ciphertext.as_slice(), &iv);
        assert_eq!(result, plaintext);
    }
}
