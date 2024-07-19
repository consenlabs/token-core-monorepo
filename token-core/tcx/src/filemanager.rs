use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use tcx_keystore::Keystore;

use crate::error_handling::Result;

lazy_static! {
    pub static ref KEYSTORE_MAP: RwLock<HashMap<String, Keystore>> = RwLock::new(HashMap::new());
    pub static ref WALLET_FILE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
    pub static ref LEGACY_WALLET_FILE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
    pub static ref KEYSTORE_BASE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
    pub static ref IS_DEBUG: RwLock<bool> = RwLock::new(false);
}

pub const WALLET_V1_DIR: &str = "wallets";
pub const WALLET_V2_DIR: &str = "walletsV2";

pub fn clean_keystore() {
    KEYSTORE_MAP.write().clear()
}

pub fn cache_keystore(keystore: Keystore) {
    let mut map = KEYSTORE_MAP.write();
    map.remove(&keystore.id());
    map.insert(keystore.id(), keystore);
}

pub fn flush_keystore(ks: &Keystore) -> Result<()> {
    let json = ks.to_json();
    let file_dir = WALLET_FILE_DIR.read();
    let ks_path = format!("{}/{}.json", file_dir, ks.id());
    let path = Path::new(&ks_path);
    let mut file = fs::File::create(path)?;
    let _ = file.write_all(json.as_bytes());
    Ok(())
}

pub fn delete_keystore_file(wid: &str) -> Result<()> {
    let file_dir = WALLET_FILE_DIR.read();
    let ks_path = format!("{}/{}.json", file_dir, wid);
    let path = Path::new(&ks_path);
    fs::remove_file(path)?;
    Ok(())
}

pub fn exist_migrated_file(id: &str) -> bool {
    let file_dir = WALLET_FILE_DIR.read();
    let ks_path = format!("{}/{}.json", file_dir, id);
    let path = Path::new(&ks_path);
    path.exists()
}
