use crate::identity::IdentityKeystore;
use crate::imt_keystore::IMTKeystore;
use crate::Error;
use crate::Result;
use core::result;
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tcx_primitive;

lazy_static! {
    pub static ref WALLETS: RwLock<HashMap<String, IMTKeystore>> = RwLock::new(HashMap::new());
    pub static ref WALLET_FILE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
}

pub struct WalletManager();

impl WalletManager {
    pub fn generate_mnemonic() -> Result<String> {
        let mnemonic = tcx_primitive::generate_mnemonic();
        Ok(mnemonic)
    }

    pub fn create_wallet(imtKeystore: IMTKeystore) -> Result<()> {
        let file_dir = WALLET_FILE_DIR.read();
        let ks_path = format!("{}/{}{}", file_dir, imtKeystore.id, ".json");
        let path = Path::new(&ks_path);
        let mut file = fs::File::create(path)?;
        let json = imtKeystore.to_json()?;
        let _ = file.write_all(&json.as_bytes());

        WALLETS
            .write()
            .insert(imtKeystore.id.to_owned(), imtKeystore);
        Ok(())
    }

    fn clear_keystore_map() {
        WALLETS.write().clear()
    }

    fn remove_wallet(id: &str, password: &str) -> Result<()> {
        let imt_keystore = Self::must_find_wallet_by_id(id)?;
        //TODO
        Ok(())
    }

    fn must_find_wallet_by_id(id: &str) -> Result<IMTKeystore> {
        let mut map = WALLETS.write();
        match map.get(id) {
            Some(keystore) => Ok(keystore.to_owned()),
            _ => Err(Error::WalletInvalidType.into()),
        }
    }

    pub fn get_wallets(identity_keystore: IdentityKeystore) -> Result<Vec<IMTKeystore>> {
        let ids = identity_keystore.to_owned().wallet_ids;
        let dir = WALLET_FILE_DIR.read();

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
            wallets.insert(id, imt_keystore);
        }
        Ok(ret_wallets)
    }
}
