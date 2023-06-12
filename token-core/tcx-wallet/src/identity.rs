use crate::constants::{CHAIN_TYPE_ETHEREUM, ETHEREUM_PATH};
use crate::imt_keystore::IMTKeystore;
use crate::model::Metadata;
use crate::wallet_manager::WalletManager;
use crate::wallet_manager::WALLET_KEYSTORE_DIR;
use crate::Error;
use crate::Result as SelfResult;
use bip39::{Language, Mnemonic, Seed};
use bitcoin::network::constants::Network;
use bitcoin::util::base58;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::key::PrivateKey;
use hmac_sha256::HMAC;
use lazy_static::lazy_static;
use multihash::{Code, MultihashDigest};
use parking_lot::RwLock;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tcx_crypto::{Crypto, EncPair, Key, Pbkdf2Params};
use uuid::Uuid;

lazy_static! {
    pub static ref IDENTITY_KEYSTORE: RwLock<IdentityKeystore> =
        RwLock::new(IdentityKeystore::default());
}

pub const IDENTITY_KEYSTORE_FILE_NAME: &'static str = "identity.json";
pub const VERSION: u32 = 1000;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IdentityKeystore {
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

impl IdentityKeystore {
    pub fn create_identity(
        metadata: Metadata,
        password: &str,
        mnemonic_phrase: &str,
    ) -> SelfResult<IdentityKeystore> {
        let network_type = match metadata.is_main_net() {
            true => Network::Bitcoin,
            _ => Network::Testnet,
        };

        Mnemonic::validate(mnemonic_phrase, Language::English).unwrap();
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let master_key = ExtendedPrivKey::new_master(network_type, seed.as_ref())?;

        let salt = match metadata.is_main_net() {
            true => "Automatic Backup Key Mainnet",
            _ => "Automatic Backup Key Testnet",
        };
        let backup_key = HMAC::mac(salt.as_bytes(), master_key.private_key.secret_bytes());

        let authentication_key = HMAC::mac("Authentication Key".as_bytes(), backup_key);

        let auth_private_key = PrivateKey::from_slice(authentication_key.as_ref(), network_type)?;
        let secp = Secp256k1::new();
        let auth_pubkey_hash = auth_private_key.public_key(&secp).pubkey_hash();

        let network_header = match metadata.is_main_net() {
            true => 0,
            _ => 111,
        };

        let version = 2;
        let magic_hex = "0fdc0c";
        let full_identifier = format!(
            "{}{:02x}{:02x}{:02x}",
            magic_hex, network_header, version, auth_pubkey_hash
        );
        let identifier = base58::check_encode_slice(hex::decode(full_identifier)?.as_slice());

        //gen enckey
        let enc_key_bytes = HMAC::mac("Encryption Key".as_bytes(), backup_key);

        let enc_private_key = PrivateKey::new_uncompressed(
            secp256k1::SecretKey::from_slice(enc_key_bytes.as_ref())?,
            network_type,
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

        let identity_keystore = IdentityKeystore {
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

        Ok(identity_keystore)
    }

    fn derive_ethereum_wallet(
        &self,
        mnemonics_phrase: &str,
        password: &str,
    ) -> SelfResult<IMTKeystore> {
        let mut metadata = Metadata::default();
        metadata.chain_type = CHAIN_TYPE_ETHEREUM.to_string();
        metadata.password_hint = self.im_token_meta.password_hint.to_owned();
        let source = &self.im_token_meta.source.clone();
        metadata.source = source.to_string();
        metadata.name = "ETH".to_string();
        let imt_keystore = IMTKeystore::create_v3_mnemonic_keystore(
            &mut metadata,
            password,
            mnemonics_phrase,
            ETHEREUM_PATH,
        )?;
        WalletManager::create_wallet(imt_keystore.to_owned())?;
        Ok(imt_keystore)
    }

    pub fn to_json(&self) -> SelfResult<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn cache_current_identity(&self) {
        let mut identity_keystore_obj = IDENTITY_KEYSTORE.write();
        *identity_keystore_obj = self.to_owned();
    }

    pub fn flush_identity_keystore(&self) -> SelfResult<()> {
        let json = self.to_json()?;
        let file_dir = WALLET_KEYSTORE_DIR.read();
        let ks_path = format!("{}/{}", file_dir, IDENTITY_KEYSTORE_FILE_NAME);
        let path = Path::new(&ks_path);
        let mut file = fs::File::create(path)?;
        let _ = file.write_all(&json.as_bytes());
        Ok(())
    }

    pub fn export_identity(&self, password: &str) -> SelfResult<String> {
        let decrypt_data = self
            .crypto
            .decrypt_enc_pair(Key::Password(password.to_string()), &self.enc_mnemonic)?;
        Ok(String::from_utf8(decrypt_data)?)
    }

    pub fn delete_identity(&self, password: &str) -> SelfResult<()> {
        if !self.crypto.verify_password(password) {
            return Err(Error::WalletInvalidPassword.into());
        }

        let clean_wallet_keystore_result = WalletManager::clean_keystore_dir()?;
        if clean_wallet_keystore_result == () {
            WalletManager::clear_keystore_map();
            let mut identity_keystore = IDENTITY_KEYSTORE.write();
            *identity_keystore = IdentityKeystore::default();
        }

        Ok(())
    }
}

pub struct Identity();

impl Identity {
    pub fn add_wallet(id: &str) {
        let mut identity_keystore = IDENTITY_KEYSTORE.write();
        identity_keystore.wallet_ids.push(id.to_string());
    }

    pub fn get_current_identity() -> SelfResult<IdentityKeystore> {
        let mut identity_keystore_obj = IDENTITY_KEYSTORE.write();
        if !identity_keystore_obj.id.is_empty() {
            return Ok(identity_keystore_obj.to_owned());
        }
        let dir = WALLET_KEYSTORE_DIR.read();
        let path_str = format!("{}/{}", dir.as_str(), IDENTITY_KEYSTORE_FILE_NAME);
        let path = Path::new(path_str.as_str());
        if !path.exists() {
            return Err(Error::KeystoreFileNotExist.into());
        }
        let mut file = File::open(&path)?;
        let mut keystore_context = String::new();
        file.read_to_string(&mut keystore_context)?;
        let identity_keystore: IdentityKeystore = serde_json::from_str(keystore_context.as_str())?;
        *identity_keystore_obj = identity_keystore.to_owned();

        Ok(identity_keystore)
    }
}

#[cfg(test)]
mod test {
    use crate::identity::{Identity, IdentityKeystore};
    use crate::model::{Metadata, FROM_NEW_IDENTITY};
    use bitcoin::network::constants::Network;
    use tcx_constants::sample_key;
    use tcx_constants::sample_key::{MNEMONIC, PASSWORD, PASSWORD_HINT};

    #[test]
    fn test_identity() {
        let metadata = Metadata::new(
            sample_key::NAME,
            Some(PASSWORD_HINT.to_string()),
            FROM_NEW_IDENTITY,
            "TESTNET",
            None,
        )
        .unwrap();
        let identity_keystore =
            IdentityKeystore::create_identity(metadata, PASSWORD, MNEMONIC).unwrap();

        let ret = identity_keystore.flush_identity_keystore();
        assert_eq!(ret.is_ok(), true);
        identity_keystore.cache_current_identity();

        let ret = identity_keystore.derive_ethereum_wallet(MNEMONIC, PASSWORD);
        assert!(ret.is_ok());

        let imt_keystore = ret.unwrap();
        let id = imt_keystore.id.as_str();
        Identity::add_wallet(id);

        let ret = Identity::get_current_identity();
        assert_eq!(ret.is_ok(), true);
        assert_eq!(ret.unwrap().wallet_ids.get(0).unwrap(), id);
        // assert_eq!(ret.unwrap().wallet_ids.get(0).unwrap(), "cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2")
    }
}
