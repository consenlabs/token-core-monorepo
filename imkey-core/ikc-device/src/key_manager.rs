use crate::error::BindError;
use crate::Result;
use base64::{decode, encode};
use ikc_common::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use ikc_common::utility::is_valid_hex;
use ring::digest;
use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

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
        let seid_hash = digest::digest(&digest::SHA256, seid.as_bytes())
            .as_ref()
            .to_vec();
        let sn_hash = digest::digest(&digest::SHA256, sn.as_bytes())
            .as_ref()
            .to_vec();

        let mut xor_result: Vec<u8> = vec![];
        for (index, value) in seid_hash.iter().enumerate() {
            xor_result.push(value ^ sn_hash.get(index).unwrap());
        }
        self.encry_key = xor_result[..16].to_vec();
        self.iv = xor_result[16..].to_vec();
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
        let hash = digest::digest(&digest::SHA256, data.as_slice());
        data.extend(hash.as_ref()[..4].iter());

        //AES-CBC encryption
        // type Aes128Cbc = Cbc<Aes128, Pkcs7>;
        // let cipher = Aes128Cbc::new_var(self.encry_key.as_ref(), self.iv.as_ref())
        //     .expect("aes_128cbc_encrypt_error");
        // let ciphertext = cipher.encrypt_vec(data.as_ref());
        let ciphertext = encrypt_pkcs7(&self.encry_key, &self.iv, &data)?;

        //base64 coding
        Ok(encode(&ciphertext))
    }

    /**
    Get key file data
    */
    pub fn get_key_file_data(path: &str, seid: &str) -> Result<String> {
        let mut return_data = String::new();
        // !!! compatibility issue, the path of key file in android is different with ios before 2.0.0
        let android_path = format!("{}/keys{}", path, seid[seid.len() - 8..].to_string());
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
                    .expect("imkey_keyfile_io_error");
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
            true => hex::decode(ciphertext).expect("invalid keys"),
            false => decode(ciphertext.as_bytes()).expect("invalid keys"), //base64 decode
        };

        //AES-CBC Decrypt
        let plaintext = decrypt_pkcs7(&ciphertext_bytes, &self.encry_key, &self.iv);
        if plaintext.is_err() {
            return Ok(false);
        }
        let decrypted_data = plaintext?;

        //Parsing data
        //pri_key
        self.pri_key = decrypted_data[..32].to_vec();

        //pub key
        self.pub_key = decrypted_data[32..97].to_vec();

        //se pub key
        self.se_pub_key = decrypted_data[97..162].to_vec();

        //session key
        self.session_key = decrypted_data[162..178].to_vec();

        //check sum
        self.check_sum = decrypted_data[178..].to_vec();

        //check checksum
        let data = &decrypted_data[..178];
        let data_hash = digest::digest(&digest::SHA256, data);
        let data_hash_byte = data_hash.as_ref();
        for (index, val) in self.check_sum.iter().enumerate() {
            if val != &data_hash_byte[index] {
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
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        self.pri_key = sk.secret_bytes().to_vec();
        self.pub_key = pk.serialize_uncompressed().to_vec();
        Ok(())
    }
    /**
     Store key data
    */
    pub fn save_keys_to_local_file(keys: &String, path: &String, seid: &String) -> Result<()> {
        if !Path::new(path).exists() {
            fs::create_dir_all(path)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(Path::new(
                format!("{}/keys{}", path, seid[seid.len() - 8..].to_string()).as_str(),
            ))
            .expect("imkey_keyfile_opertion_error");
        match file.write_all(keys.as_bytes()) {
            Ok(val) => Ok(val),
            Err(_e) => Err(BindError::ImkeySaveKeyFileFail.into()),
        }
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
        key_manager_obj.gen_encrypt_key(&seid, &sn);
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
}
