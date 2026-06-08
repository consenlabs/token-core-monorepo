use crate::error::BindError;
use crate::Result;
use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use ikc_common::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use ikc_common::utility::{is_valid_hex, sha256_hash};
use secp256k1::rand::rand_core::UnwrapErr;
use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

const PRIVATE_KEY_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 65;
const SE_PUBLIC_KEY_LEN: usize = 65;
const SESSION_KEY_LEN: usize = 16;
const CHECKSUM_LEN: usize = 4;
const KEY_DATA_LEN: usize = PRIVATE_KEY_LEN + PUBLIC_KEY_LEN + SE_PUBLIC_KEY_LEN + SESSION_KEY_LEN;
const KEY_FILE_PLAINTEXT_LEN: usize = KEY_DATA_LEN + CHECKSUM_LEN;

pub struct KeyManager {
    pub pri_key: Vec<u8>,
    //32 byte
    pub pub_key: Vec<u8>,
    //65 byte
    pub se_pub_key: Vec<u8>,
    //65 byte
    pub session_key: Vec<u8>,
    //16 byte
    pub check_sum: Vec<u8>,
    //4 byte
    pub encry_key: Vec<u8>,
    //16 byte
    pub iv: Vec<u8>, //16 byte
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager {
    pub fn new() -> KeyManager {
        KeyManager {
            pri_key: vec![],
            pub_key: vec![],
            se_pub_key: vec![],
            session_key: vec![],
            check_sum: vec![],
            encry_key: vec![],
            iv: vec![],
        }
    }
    /**
    Generate encryption key
    */
    pub fn gen_encrypt_key(&mut self, seid: &str, sn: &str) {
        //calc seid and sn hash
        let seid_hash = sha256_hash(seid.as_bytes());
        let sn_hash = sha256_hash(sn.as_bytes());

        let mut xor_result: Vec<u8> = vec![];
        for (seid_value, sn_value) in seid_hash.iter().zip(sn_hash.iter()) {
            xor_result.push(seid_value ^ sn_value);
        }
        self.encry_key = xor_result[..16].to_vec();
        self.iv = xor_result[16..32].to_vec();
    }

    /**
    Organize and encrypt key file data
    */
    pub fn encrypt_data(&self) -> Result<String> {
        let mut data = vec![];
        //
        data.extend(self.pri_key.iter());
        data.extend(self.pub_key.iter());
        data.extend(self.se_pub_key.iter());
        data.extend(self.session_key.iter());

        //calc HASH
        let hash = sha256_hash(data.as_slice());
        data.extend(&hash[..4]);

        //AES-CBC encryption
        let ciphertext = encrypt_pkcs7(&data, &self.encry_key, &self.iv)?;

        //base64 coding
        Ok(BASE64_STANDARD.encode(&ciphertext))
    }

    /**
    Get key file data
    */
    pub fn get_key_file_data(path: &str, seid: &str) -> Result<String> {
        let mut return_data = String::new();
        // !!! compatibility issue, the path of key file in android is different with ios before 2.0.0
        let android_path = format!("{}/keys{}", path, Self::key_file_suffix(seid)?);
        let ios_path = format!("{}/keys{}", path, seid);
        let path = if Path::new(android_path.as_str()).exists() {
            android_path
        } else {
            ios_path
        };
        let file = File::open(&path);
        match file {
            Ok(mut f) => {
                f.read_to_string(&mut return_data)
                    .map_err(|_| BindError::ImkeyKeyfileIoError)?;
                Ok(return_data)
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(return_data),
                _ => Err(BindError::ImkeyKeyfileIoError.into()),
            },
        }
    }

    /**
    Decrypt key file data
    */
    pub fn decrypt_keys(&mut self, ciphertext: &str) -> Result<bool> {
        let ciphertext_bytes = match is_valid_hex(ciphertext) {
            true => match hex::decode(ciphertext) {
                Ok(data) => data,
                Err(_) => return Ok(false),
            },
            false => match BASE64_STANDARD.decode(ciphertext.as_bytes()) {
                Ok(data) => data,
                Err(_) => return Ok(false),
            },
        };

        //AES-CBC Decrypt
        let plaintext = decrypt_pkcs7(&ciphertext_bytes, &self.encry_key, &self.iv);
        if plaintext.is_err() {
            return Ok(false);
        }
        let decrypted_data = plaintext?;
        if decrypted_data.len() != KEY_FILE_PLAINTEXT_LEN {
            return Ok(false);
        }

        //Parsing data
        //pri_key
        self.pri_key = decrypted_data[..PRIVATE_KEY_LEN].to_vec();

        //pub key
        let pub_key_start = PRIVATE_KEY_LEN;
        let pub_key_end = pub_key_start + PUBLIC_KEY_LEN;
        self.pub_key = decrypted_data[pub_key_start..pub_key_end].to_vec();

        //se pub key
        let se_pub_key_end = pub_key_end + SE_PUBLIC_KEY_LEN;
        self.se_pub_key = decrypted_data[pub_key_end..se_pub_key_end].to_vec();

        //session key
        self.session_key = decrypted_data[se_pub_key_end..KEY_DATA_LEN].to_vec();

        //check sum
        self.check_sum = decrypted_data[KEY_DATA_LEN..].to_vec();

        //check checksum
        let data = &decrypted_data[..KEY_DATA_LEN];
        let data_hash = sha256_hash(data);
        for (val, expected) in self.check_sum.iter().zip(data_hash.iter()) {
            if val != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /**
    gen local key pair
    */
    pub fn gen_local_keys(&mut self) -> Result<()> {
        let secp = Secp256k1::new();
        let mut rng = UnwrapErr(OsRng);
        let (sk, pk) = secp.generate_keypair(&mut rng);
        self.pri_key = sk.secret_bytes().to_vec();
        self.pub_key = pk.serialize_uncompressed().to_vec();
        Ok(())
    }
    /**
     Store key data
    */
    pub fn save_keys_to_local_file(keys: &str, path: &str, seid: &str) -> Result<()> {
        if !Path::new(path).exists() {
            fs::create_dir_all(path)?;
        }

        let key_path = format!("{}/keys{}", path, Self::key_file_suffix(seid)?);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(Path::new(key_path.as_str()))
            .map_err(|_| BindError::ImkeySaveKeyFileFail)?;
        match file.write_all(keys.as_bytes()) {
            Ok(val) => Ok(val),
            Err(_e) => Err(BindError::ImkeySaveKeyFileFail.into()),
        }
    }

    fn key_file_suffix(seid: &str) -> Result<&str> {
        let suffix_start = seid
            .len()
            .checked_sub(8)
            .ok_or_else(|| anyhow!("imkey_sdk_illegal_argument"))?;
        seid.get(suffix_start..)
            .ok_or_else(|| BindError::ImkeySdkIllegalArgument.into())
    }
}

#[cfg(test)]
mod test {
    use crate::key_manager::KeyManager;

    #[test]
    fn gen_encrypt_key_test() {
        let seid = "19060000000200860001010000000014";
        let sn = "imKey01191200001";
        let mut key_manager_obj = KeyManager::new();
        key_manager_obj.gen_encrypt_key(seid, sn);
        println!(
            "encry key-->{:?}",
            hex::encode_upper(&key_manager_obj.encry_key)
        );
        println!("iv-->{:?}", hex::encode_upper(&key_manager_obj.iv));
        assert_eq!(
            hex::encode_upper(key_manager_obj.encry_key),
            "A49CDEDE0370D1543033E41A413EBC4E".to_string()
        );
        assert_eq!(
            hex::encode_upper(key_manager_obj.iv),
            "92AF372F64C10BAA942478560F91F346".to_string()
        );
    }

    #[test]
    fn decrypt_invalid_key_data_returns_false() {
        let mut key_manager_obj = KeyManager::new();
        assert!(!key_manager_obj.decrypt_keys("not-valid-key-data").unwrap());
    }

    #[test]
    fn short_seid_key_file_suffix_returns_error() {
        assert!(KeyManager::key_file_suffix("1234567").is_err());
    }
}
