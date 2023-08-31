use crate::constants::{CHAIN_TYPE_ETHEREUM, ETHEREUM_PATH};
use crate::imt_keystore::{IMTKeystore, WALLETS, WALLET_KEYSTORE_DIR};
use crate::model::{Metadata, FROM_NEW_IDENTITY, FROM_RECOVERED_IDENTITY};
use crate::wallet_api::{CreateIdentityParam, RecoverIdentityParam};
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
use tcx_crypto::{Crypto, EncPair, Key};
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
    pub crypto: Crypto,
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
    pub fn new(
        metadata: Metadata,
        password: &str,
        mnemonic_phrase: &str,
    ) -> SelfResult<IdentityKeystore> {
        let network_type = match metadata.is_main_net() {
            true => Network::Bitcoin,
            _ => Network::Testnet,
        };

        let validate_result = Mnemonic::validate(mnemonic_phrase, Language::English);
        if validate_result.is_err() {
            return Err(Error::InvalidMnemonic.into());
        }
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

        let mut crypto: Crypto = Crypto::new(password, master_prikey_bytes.as_bytes());
        let unlocker = crypto.use_key(&Key::Password(password.to_string()))?;

        let enc_auth_key = unlocker.encrypt_with_random_iv(authentication_key.as_slice())?;
        let enc_mnemonic = unlocker.encrypt_with_random_iv(mnemonic.phrase().as_bytes())?;

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

    pub fn to_json(&self) -> SelfResult<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn cache(&self) {
        let mut identity_keystore_obj = IDENTITY_KEYSTORE.write();
        *identity_keystore_obj = self.to_owned();
    }

    pub fn flush(&self) -> SelfResult<()> {
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
            .use_key(&Key::Password(password.to_string()))?
            .plaintext()?;
        Ok(String::from_utf8(decrypt_data)?)
    }

    pub fn delete_identity(&self, password: &str) -> SelfResult<()> {
        if !self.crypto.verify_password(password) {
            return Err(Error::WalletInvalidPassword.into());
        }

        let clean_wallet_keystore_result = IMTKeystore::clean_keystore_dir();
        if clean_wallet_keystore_result.is_ok() {
            IMTKeystore::clear_keystore_map();
            let mut identity_keystore = IDENTITY_KEYSTORE.write();
            *identity_keystore = IdentityKeystore::default();
        }

        Ok(())
    }

    pub fn get_wallets(&self) -> SelfResult<Vec<IMTKeystore>> {
        let ids = &self.wallet_ids;
        let dir = WALLET_KEYSTORE_DIR.read();

        let mut wallets = WALLETS.write();
        let mut ret_wallets = Vec::new();
        let mut keystore_context = String::new();
        for id in ids {
            if wallets.get(id.as_str()).is_some() {
                ret_wallets.push(wallets.get(id.as_str()).unwrap().clone());
                continue;
            }

            let path_str = format!("{}/{}.json", dir.as_str(), id);
            let path = Path::new(path_str.as_str());
            if !path.exists() {
                return Err(Error::KeystoreFileNotExist.into());
            }
            let mut file = File::open(&path)?;
            file.read_to_string(&mut keystore_context)?;
            let imt_keystore: IMTKeystore = serde_json::from_str(keystore_context.as_str())?;
            ret_wallets.push(imt_keystore.to_owned());
            wallets.insert(id.to_string(), imt_keystore);
        }
        Ok(ret_wallets)
    }
}

pub struct Identity();

impl Identity {
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

    pub fn create_identity(param: CreateIdentityParam) -> SelfResult<IdentityKeystore> {
        let name = param.name.as_str();
        let password = param.password.as_str();
        let password_hint = param.password_hint;
        let network = param.network.as_str();
        let seg_wit = param.seg_wit.as_deref();
        let mnemonic_phrase = tcx_primitive::generate_mnemonic();

        let metadata = Metadata::new(
            name,
            password_hint.clone(),
            FROM_NEW_IDENTITY,
            network,
            None,
            seg_wit,
        )?;
        let mut identity_keystore =
            IdentityKeystore::new(metadata.clone(), password, mnemonic_phrase.as_str())?;

        let eth_keystore = Self::derive_ethereum_wallet(
            password_hint,
            FROM_NEW_IDENTITY,
            mnemonic_phrase.as_str(),
            password,
        )?;

        identity_keystore.wallet_ids.push(eth_keystore.id);
        identity_keystore.flush()?;
        identity_keystore.cache();

        Ok(identity_keystore)
    }

    pub fn recover_identity(param: RecoverIdentityParam) -> SelfResult<IdentityKeystore> {
        let name = param.name.as_str();
        let password = param.password.as_str();
        let password_hint = param.password_hint;
        let network = param.network.as_str();
        let seg_wit = param.seg_wit.as_deref();
        let mnemonic_phrase = param.mnemonic.as_str();
        let metadata = Metadata::new(
            name,
            password_hint.clone(),
            FROM_RECOVERED_IDENTITY,
            network,
            None,
            seg_wit,
        )?;
        let mut identity_keystore = IdentityKeystore::new(metadata, password, mnemonic_phrase)?;
        let eth_keystore = Self::derive_ethereum_wallet(
            password_hint,
            FROM_RECOVERED_IDENTITY,
            mnemonic_phrase,
            password,
        )?;

        identity_keystore.wallet_ids.push(eth_keystore.id);
        identity_keystore.flush()?;
        identity_keystore.cache();

        Ok(identity_keystore)
    }

    fn derive_ethereum_wallet(
        password_hint: Option<String>,
        source: &str,
        mnemonic_phrase: &str,
        password: &str,
    ) -> SelfResult<IMTKeystore> {
        let mut metadata = Metadata::default();
        metadata.chain_type = Some(CHAIN_TYPE_ETHEREUM.to_string());
        metadata.password_hint = password_hint;
        metadata.source = source.to_string();
        metadata.name = "ETH".to_string();
        let imt_keystore = IMTKeystore::create_v3_mnemonic_keystore(
            &mut metadata,
            password,
            mnemonic_phrase,
            ETHEREUM_PATH,
        )?;
        imt_keystore.create_wallet()?;
        Ok(imt_keystore)
    }
}

#[cfg(test)]
mod test {
    use crate::identity::Identity;
    use crate::model::FROM_NEW_IDENTITY;
    use crate::wallet_api::{CreateIdentityParam, RecoverIdentityParam};
    use tcx_constants::sample_key;
    use tcx_constants::sample_key::{MNEMONIC, NAME, PASSWORD, PASSWORD_HINT};

    #[test]
    fn test_create_identity() {
        let param = CreateIdentityParam {
            name: sample_key::NAME.to_string(),
            password: PASSWORD.to_string(),
            password_hint: Some(PASSWORD_HINT.to_string()),
            network: "TESTNET".to_string(),
            seg_wit: None,
        };
        let identity_keystore = Identity::create_identity(param).unwrap();
        let imt_keystore_id = identity_keystore.wallet_ids.get(0).unwrap();
        let ret = Identity::get_current_identity();
        assert_eq!(ret.is_ok(), true);
        assert_eq!(ret.unwrap().wallet_ids.get(0).unwrap(), imt_keystore_id);
    }

    #[test]
    fn test_recover_identity() {
        let param = RecoverIdentityParam {
            name: NAME.to_string(),
            mnemonic: MNEMONIC.to_string(),
            password: PASSWORD.to_string(),
            password_hint: Some(PASSWORD_HINT.to_string()),
            network: "TESTNET".to_string(),
            seg_wit: None,
        };
        let recover_result = Identity::recover_identity(param);
        assert_eq!(recover_result.is_ok(), true);
        let identity_keystore = Identity::get_current_identity().unwrap();
        let wallets = identity_keystore.get_wallets().unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(
            "6031564e7b2f5cc33737807b2e58daff870b590b",
            wallets.get(0).unwrap().address
        );
    }
}
