use crate::model::{Metadata, FROM_NEW_IDENTITY};
use crate::wallet_manager::generate_Mnemonic;
use crate::Result as SelfResult;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use bitcoin::network::constants::Network;
use bitcoin::util::base58;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::key::{PrivateKey, PublicKey};
use hex::{FromHex, ToHex};
use hmac_sha256::HMAC;
use lazy_static::lazy_static;
use multihash::{Code, MultihashDigest};
use parking_lot::RwLock;
use secp256k1::Secp256k1;
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use std::hash::Hash;
use tcx_crypto::hash::hex_dsha256;
use tcx_crypto::{Crypto, EncPair, Pbkdf2Params};
use uuid::Uuid;

pub const VERSION: u32 = 1000;

lazy_static! {
    pub static ref IDENTITY_KEYSTORE: RwLock<Keystore> = RwLock::new(Keystore::default());
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Keystore {
    pub crypto: Crypto<Pbkdf2Params>,
    pub id: String,
    pub version: u32,
    pub enc_auth_key: EncPair,
    pub enc_key: String,
    pub enc_mnemonic: EncPair,
    pub identifier: String,
    pub ipfs_id: String,
    #[serde(rename = "walletIDs")]
    pub wallet_ids: Vec<String>,
    pub im_token_meta: Metadata,
}

impl Keystore {
    pub fn create_identity(
        name: &str,
        password: &str,
        password_hit: &str,
        network: Network,
        seg_wit: Option<&str>,
    ) -> SelfResult<Keystore> {
        let metadata = Metadata::new(
            name,
            password_hit,
            FROM_NEW_IDENTITY,
            network.to_string().as_str(),
            seg_wit,
        )?;
        //生成助记词
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        //助记词验证
        Mnemonic::validate(mnemonic.phrase(), Language::English).unwrap();
        //通过助记词获取seed
        let seed = Seed::new(&mnemonic, "");
        //通过seed获取master key
        let master_key = ExtendedPrivKey::new_master(network, seed.as_ref())?;

        let salt = match metadata.is_main_net() {
            true => "Automatic Backup Key Mainnet",
            _ => "Automatic Backup Key Testnet",
        };
        let backup_key = HMAC::mac(salt.as_bytes(), master_key.private_key.secret_bytes());

        let authentication_key = HMAC::mac("Authentication Key".as_bytes(), backup_key);

        let auth_private_key =
            PrivateKey::from_slice(authentication_key.as_ref(), Network::Bitcoin)?;
        let secp = Secp256k1::new();
        let auth_pubkey_hash = auth_private_key.public_key(&secp).pubkey_hash();

        let networkHeader = match metadata.is_main_net() {
            true => 0,
            _ => 111,
        };

        //
        let version = 2;
        let magic_hex = "0fdc0c";
        let full_identifier = format!(
            "{}{:02x}{:02x}{:02x}",
            magic_hex, networkHeader, version, auth_pubkey_hash
        );
        let identifier = base58::check_encode_slice(hex::decode(full_identifier)?.as_slice());

        //gen enckey
        let enc_key_bytes = HMAC::mac("Encryption Key".as_bytes(), backup_key);

        let enc_private_key = PrivateKey::new_uncompressed(
            secp256k1::SecretKey::from_slice(enc_key_bytes.as_ref())?,
            Network::Bitcoin,
        );
        let multihash =
            Code::Sha2_256.digest(enc_private_key.public_key(&secp).to_bytes().as_slice());
        let ipfs_id = base58::encode_slice(&multihash.to_bytes());

        let master_prikey_bytes = master_key.encode();
        let master_prikey_bytes = base58::check_encode_slice(master_prikey_bytes.as_slice());

        let mut crypto: Crypto<Pbkdf2Params> =
            Crypto::new_by_10240_round(password, master_prikey_bytes.as_bytes());
        let enc_auth_key = crypto.derive_enc_pair(password, authentication_key.as_slice())?;
        let enc_mnemonic = crypto.derive_enc_pair(password, mnemonic.phrase().as_bytes())?;
        crypto.clear_cache_derived_key();

        let keystore = Keystore {
            crypto,
            id: Uuid::new_v4().as_hyphenated().to_string(),
            version: VERSION,
            enc_auth_key,
            enc_key: hex::encode(enc_key_bytes),
            enc_mnemonic,
            identifier,
            ipfs_id,
            wallet_ids: vec![],
            im_token_meta: metadata,
        };
        let mut keystore_obj = IDENTITY_KEYSTORE.write();
        *keystore_obj = keystore.clone();
        Ok(keystore)
    }

    pub fn to_json(&self) -> SelfResult<String> {
        Ok(serde_json::to_string(&self)?)
    }
}

fn create_identity(
    name: &str,
    password: &str,
    password_hit: &str,
    network: &str,
    seg_wit: Option<&str>,
) {
    //生成助记词
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    println!("{}", phrase);
}

#[cfg(test)]
mod test {
    use crate::identity::{create_identity, Keystore};
    use bitcoin::network::constants::Network;

    #[test]
    fn test_create_identity() {
        create_identity("name", "123456", "password_hit", "mainnet", None);
    }

    #[test]
    fn test_keystore_create_identity() {
        Keystore::create_identity(
            "xyz",
            "Insecure Pa55w0rd",
            "Password Hint",
            Network::Testnet,
            None,
        );
    }
}
