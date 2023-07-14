use crate::constants::CHAIN_TYPE_ETHEREUM;
use crate::model::Metadata;
use crate::Error;
use crate::Result;
use bip39::{Language, Mnemonic};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tcx_crypto::{Crypto, EncPair, Key, Pbkdf2Params};
// use tcx_eth::address::EthAddress;
use parking_lot::RwLock;
use std::collections::HashMap;
use tcx_common::util::get_address_from_pubkey;
use tcx_primitive::{Bip32DeterministicPrivateKey, Derive, DeterministicPrivateKey, PrivateKey};
use uuid::Uuid;

pub const VERSION: u32 = 3;

lazy_static! {
    pub static ref WALLETS: RwLock<HashMap<String, IMTKeystore>> = RwLock::new(HashMap::new());
    pub static ref WALLET_KEYSTORE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IMTKeystore {
    pub crypto: Crypto<Pbkdf2Params>,
    pub id: String,
    pub version: u32,
    pub address: String,
    pub mnemonic_path: String,
    pub enc_mnemonic: EncPair,
    pub im_token_meta: Metadata,
}

impl IMTKeystore {
    pub fn create_v3_mnemonic_keystore(
        metadata: &mut Metadata,
        password: &str,
        mnemonic_phrase: &str,
        path: &str,
    ) -> Result<IMTKeystore> {
        Mnemonic::validate(mnemonic_phrase, Language::English).unwrap();

        let bip32_deterministic_private_key =
            Bip32DeterministicPrivateKey::from_mnemonic(mnemonic_phrase)?;
        let bip32_deterministic_private_key = bip32_deterministic_private_key.derive(path)?;

        let mut crypto: Crypto<Pbkdf2Params> = Crypto::new_by_10240_round(
            password,
            bip32_deterministic_private_key
                .private_key()
                .0
                .to_bytes()
                .as_slice(),
        );
        let enc_mnemonic = crypto.derive_enc_pair(password, mnemonic_phrase.as_bytes())?;
        crypto.clear_cache_derived_key();
        metadata.timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();

        let publick_key = bip32_deterministic_private_key
            .private_key()
            .public_key()
            .to_uncompressed();

        let address = get_address(
            metadata.chain_type.as_str(),
            metadata.is_main_net(),
            publick_key.as_slice(),
        )?;

        Ok(IMTKeystore {
            crypto,
            id: Uuid::new_v4().as_hyphenated().to_string(),
            version: VERSION,
            address,
            mnemonic_path: path.to_string(),
            enc_mnemonic,
            im_token_meta: metadata.clone(),
        })
    }

    #[warn(dead_code)]
    pub fn create_hd_mnemonic_keystore(
        _metadata: &mut Metadata,
        _password: &str,
        _mnemonic_phrase: &str,
        _path: &str,
        _id: Option<&str>,
    ) -> Result<IMTKeystore> {
        unimplemented!();
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn decrypt_main_key(&self, password: &str) -> Result<Vec<u8>> {
        self.crypto.decrypt(Key::Password(password.to_owned()))
    }
}

impl IMTKeystore {
    pub fn create_wallet(&self) -> Result<()> {
        let file_dir = WALLET_KEYSTORE_DIR.read();
        let ks_path = format!("{}/{}.json", file_dir, self.id);
        let path = Path::new(&ks_path);
        let mut file = fs::File::create(path)?;
        let json = self.to_json()?;
        let _ = file.write_all(&json.as_bytes());

        WALLETS.write().insert(self.id.to_string(), self.to_owned());
        Ok(())
    }

    pub fn clear_keystore_map() {
        WALLETS.write().clear();
    }

    pub fn must_find_wallet_by_id(id: &str) -> Result<IMTKeystore> {
        let map = WALLETS.write();
        match map.get(id) {
            Some(keystore) => Ok(keystore.to_owned()),
            _ => Err(Error::WalletNotFound.into()),
        }
    }

    pub fn clean_keystore_dir() -> Result<()> {
        let dir = WALLET_KEYSTORE_DIR.read();
        let paths = fs::read_dir(dir.as_str()).unwrap();
        for path in paths {
            let path = path?.path();
            if path.is_file() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

fn get_address(chain_type: &str, _is_mainnet: bool, public_key: &[u8]) -> Result<String> {
    let address = match chain_type {
        CHAIN_TYPE_ETHEREUM => get_address_from_pubkey(public_key)?,
        _ => return Err(Error::WalletInvalidType.into()),
    };
    Ok(address)
}

#[cfg(test)]
mod test {
    use crate::constants;
    use crate::constants::{CHAIN_TYPE_ETHEREUM, ETHEREUM_PATH};
    use crate::imt_keystore::{get_address, IMTKeystore};
    use crate::model::{Metadata, FROM_NEW_IDENTITY};
    use tcx_constants::sample_key::{MNEMONIC, PASSWORD, PASSWORD_HINT};
    #[test]
    fn test_get_address() {
        let public_key = hex::decode("0480c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fefbc790fc3291d3cb6441ac94c3952035c409f4374d1780f400c1ed92972ce83c").unwrap();
        let address = get_address(constants::CHAIN_TYPE_ETHEREUM, false, public_key.as_slice());
        assert!(address.is_ok());
        assert_eq!(address.unwrap(), "6031564e7b2f5cc33737807b2e58daff870b590b");

        let address = get_address("WRONG_CHAIN_TYPE", false, public_key.as_slice());
        assert!(address.is_err());
    }

    #[test]
    fn test_create_v3_mnemonic_keystore() {
        let mut metadata = Metadata::default();
        metadata.chain_type = CHAIN_TYPE_ETHEREUM.to_string();
        metadata.password_hint = Some(PASSWORD_HINT.to_string());
        metadata.source = FROM_NEW_IDENTITY.to_string();
        metadata.name = "ETH".to_string();
        let imt_keystore = IMTKeystore::create_v3_mnemonic_keystore(
            &mut metadata,
            PASSWORD,
            MNEMONIC,
            ETHEREUM_PATH,
        )
        .unwrap();
        assert_eq!(
            imt_keystore.address,
            "6031564e7b2f5cc33737807b2e58daff870b590b"
        );
        assert_eq!(
            hex::encode(imt_keystore.decrypt_main_key(PASSWORD).unwrap()),
            "cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2"
        );
    }
}
