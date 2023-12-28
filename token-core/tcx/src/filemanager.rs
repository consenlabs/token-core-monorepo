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
    pub static ref KEYSTORE_BASE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
    pub static ref IS_DEBUG: RwLock<bool> = RwLock::new(false);
}

pub const WALLET_V1_DIR: &str = "wallets";
pub const WALLET_V2_DIR: &str = "walletsV2";

pub fn copy_to_v2_if_need() -> Result<()> {
    let base = KEYSTORE_BASE_DIR.read();
    let v1_path = format!("{}/{}", base, WALLET_V1_DIR);
    let v2_path = format!("{}/{}", base, WALLET_V2_DIR);

    fs::create_dir_all(&v2_path)?;

    let paths = fs::read_dir(v1_path)?;
    for path_ret in paths {
        let Ok(path) = path_ret else {
            return Err(format_err!("keystore_dir_v2_missing"));
        };

        if let Ok(meta) = path.metadata() {
            if meta.is_dir() {
                continue;
            }
        }

        let file_name_oss = path.file_name();
        let file_name_opt = file_name_oss.to_str();
        let Some(file_name) = file_name_opt else {
            return Err(format_err!("keystore_dir_v2_missing"));
        };

        let v1_file = path.path();
        let v2_file_str = if file_name.ends_with(".json") {
            format!("{}/{}", v2_path, file_name)
        } else {
            format!("{}/{}.json", v2_path, file_name)
        };
        let v2_file = Path::new(&v2_file_str);
        if !v2_file.exists() {
            fs::copy(v1_file, v2_file)?;
        }
    }

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use crate::filemanager::{KEYSTORE_BASE_DIR, WALLET_V1_DIR};

    use super::{copy_to_v2_if_need, WALLET_V2_DIR};
    use serial_test::serial;
    #[test]
    #[serial]
    fn test_backup_keystores() {
        *KEYSTORE_BASE_DIR.write() = "../test-data".to_string();
        let _v1_dir = format!("{}/{}", KEYSTORE_BASE_DIR.read(), WALLET_V1_DIR);
        let v2_dir = format!("{}/{}", KEYSTORE_BASE_DIR.read(), WALLET_V2_DIR);

        let _ = fs::remove_dir_all(&v2_dir);
        let expected_files = vec![
            "02a55ab6-554a-4e78-bc26-6a7acced7e5e.json",
            "7f5406be-b5ee-4497-948c-877deab8c994.json",
            "42c275c6-957a-49e8-9eb3-43c21cbf583f.json",
            "045861fe-0e9b-4069-92aa-0ac03cad55e0.json",
            "175169f7-5a35-4df7-93c1-1ff612168e71.json",
            "3831346d-0b81-405b-89cf-cdb1d010430e.json",
            "5991857a-2488-4546-b730-463a5f84ea6a.json",
            "identity.json",
        ];

        let exclude_files = vec!["not_keystore", "imkey/keys12345678"];

        copy_to_v2_if_need().unwrap();

        for file in expected_files {
            let file_path = format!("{}/{}", v2_dir, file);
            let path = Path::new(&file_path);
            assert!(path.exists());
        }

        for file in exclude_files {
            let file_path = format!("{}/{}", v2_dir, file);
            let path = Path::new(&file_path);
            assert!(!path.exists());
        }

        // fs::remove_dir_all(&v2_dir).unwrap();
    }
}
