use crate::numberic_util;
use crate::Error;
use crate::Result;
use bitcoin_hashes::hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use std::env;
use tiny_keccak::Hasher;

const CREDENTIAL_LEN: usize = 64usize;

pub type Credential = [u8; CREDENTIAL_LEN];

fn default_kdf_rounds() -> u32 {
    let v = env::var("KDF_ROUNDS");
    if v.is_err() {
        *crate::KDF_ROUNDS.read() as u32
    } else {
        v.unwrap().parse::<u32>().unwrap()
    }
}

#[derive(Clone)]
pub enum Key {
    Password(String),
    DerivedKey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EncPair {
    pub enc_str: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CipherParams {
    iv: String,
}

pub trait KdfParams: Default {
    fn name(&self) -> &str;
    fn validate(&self) -> Result<()>;
    fn derive_key(&self, password: &[u8], out: &mut [u8]);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Pbkdf2Params {
    c: u32,
    prf: String,
    dklen: u32,
    salt: String,
}

impl Default for Pbkdf2Params {
    fn default() -> Pbkdf2Params {
        Pbkdf2Params {
            c: default_kdf_rounds(),
            prf: "hmac-sha256".to_owned(),
            dklen: 32,
            salt: "".to_owned(),
        }
    }
}

impl KdfParams for Pbkdf2Params {
    fn name(&self) -> &str {
        "pbkdf2"
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0 || self.c == 0 || self.salt.is_empty() || self.prf.is_empty() {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) {
        let salt_bytes: Vec<u8> = FromHex::from_hex(&self.salt).unwrap();
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &salt_bytes, self.c, out);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SCryptParams {
    n: u32,
    p: u32,
    r: u32,
    dklen: u32,
    salt: String,
}

impl Default for SCryptParams {
    fn default() -> Self {
        SCryptParams {
            dklen: 32,
            n: 262144,
            p: 1,
            r: 8,
            salt: "".to_string(),
        }
    }
}

impl KdfParams for SCryptParams {
    fn name(&self) -> &str {
        "scrypt"
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0 || self.n == 0 || self.salt.is_empty() || self.p == 0 || self.r == 0 {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) {
        let salt_bytes: Vec<u8> = FromHex::from_hex(&self.salt).unwrap();
        let log_n = (self.n as f64).log2().round();
        let inner_params =
            scrypt::Params::new(log_n as u8, self.r, self.p).expect("init scrypt params");

        scrypt::scrypt(password, &salt_bytes, &inner_params, out).expect("can not execute scrypt");
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheDerivedKey {
    hashed_key: String,
    derived_key: Vec<u8>,
}

impl CacheDerivedKey {
    pub fn new(key: &str, derived_key: &[u8]) -> Self {
        CacheDerivedKey {
            hashed_key: Self::hash(key),
            derived_key: derived_key.to_vec(),
        }
    }

    fn hash(key: &str) -> String {
        // hex_dsha256(key)
        let key_bytes = Vec::from_hex(key).expect("hash cache derived key");
        let hashed = tcx_common::sha256d(&key_bytes);
        hashed.to_hex()
    }

    pub fn get_derived_key(&self, key: &str) -> Result<Vec<u8>> {
        if self.hashed_key == Self::hash(key) {
            Ok(self.derived_key.clone())
        } else {
            Err(Error::PasswordIncorrect.into())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Crypto {
    cipher: String,
    cipherparams: CipherParams,
    ciphertext: String,
    #[serde(flatten)]
    kdf: KdfType,
    mac: String,
}

pub struct Unlocker<'a> {
    pub crypto: &'a Crypto,
    derived_key: Vec<u8>,
}

fn encrypt(plaintext: &[u8], derived_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = &derived_key[0..16];
    super::aes::ctr::decrypt_nopadding(plaintext, key, iv)
}

fn decrypt(ciphertext: &[u8], derived_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = &derived_key[0..16];
    super::aes::ctr::encrypt_nopadding(ciphertext, key, iv)
}

fn generate_mac(derived_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let result = [&derived_key[16..32], ciphertext].concat();
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(result.as_slice());
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output.to_vec()
}

fn encrypt_with_random_iv(derived_key: &[u8], plaintext: &[u8]) -> Result<EncPair> {
    let iv = numberic_util::random_iv(16);
    let ciphertext = encrypt(plaintext, derived_key, &iv)?;
    Ok(EncPair {
        enc_str: ciphertext.to_hex(),
        nonce: iv.to_hex(),
    })
}

fn decrypt_enc_pair(derived_key: &[u8], enc_pair: &EncPair) -> Result<Vec<u8>> {
    let ciphertext: Vec<u8> = FromHex::from_hex(&enc_pair.enc_str).unwrap();
    let iv: Vec<u8> = FromHex::from_hex(&enc_pair.nonce).unwrap();

    decrypt(&ciphertext, derived_key, &iv)
}

impl<'a> Unlocker<'a> {
    pub fn derived_key(&self) -> &[u8] {
        return &self.derived_key;
    }

    pub fn plaintext(&self) -> Result<Vec<u8>> {
        self.crypto.decrypt(self.derived_key())
    }

    pub fn encrypt_with_random_iv(&self, plaintext: &[u8]) -> Result<EncPair> {
        encrypt_with_random_iv(&self.derived_key, plaintext)
    }

    pub fn decrypt_enc_pair(&self, enc_pair: &EncPair) -> Result<Vec<u8>> {
        decrypt_enc_pair(&self.derived_key, enc_pair)
    }
}

impl Crypto {
    pub fn use_key(&self, key: &Key) -> Result<Unlocker> {
        match key {
            Key::Password(password) => {
                let derived_key = self.derive_key(password)?;

                if self.mac != "" && !self.verify_derived_key(&derived_key) {
                    return Err(Error::PasswordIncorrect.into());
                }

                Ok(Unlocker {
                    crypto: self,
                    derived_key,
                })
            }
            Key::DerivedKey(derived_key_hex) => {
                let derived_key = Vec::from_hex(derived_key_hex)?;

                if !self.verify_derived_key(&derived_key) {
                    return Err(Error::PasswordIncorrect.into());
                }

                Ok(Unlocker {
                    crypto: self,
                    derived_key,
                })
            }
        }
    }

    pub fn new(password: &str, origin: &[u8]) -> Crypto {
        let mut param = Pbkdf2Params::default();
        param.salt = numberic_util::random_iv(32).to_hex();

        Self::new_with_kdf(password, origin, KdfType::Pbkdf2(param))
    }

    pub fn new_with_kdf(password: &str, plaintext: &[u8], kdf: KdfType) -> Crypto {
        let iv = numberic_util::random_iv(16);

        let mut crypto = Crypto {
            cipher: "aes-128-ctr".to_owned(),
            cipherparams: CipherParams { iv: iv.to_hex() },
            ciphertext: String::from(""),
            kdf,
            mac: String::from(""),
        };

        let derived_key = crypto.derive_key(password).expect("derive key");
        let ciphertext = crypto.encrypt(&derived_key, plaintext).expect("encrypt");
        let mac = generate_mac(&derived_key, &ciphertext);

        crypto.ciphertext = ciphertext.to_hex();
        crypto.mac = mac.to_hex();

        crypto
    }

    /*
     * used to update the ciphertext, but without changing the the derived key.
     */
    pub fn dangerous_rewrite_plaintext(
        &mut self,
        derived_key: &[u8],
        plaintext: &[u8],
    ) -> Result<()> {
        let ciphertext = self.encrypt(&derived_key, plaintext).expect("encrypt");
        let mac = generate_mac(&derived_key, &ciphertext);

        self.ciphertext = ciphertext.to_hex();
        self.mac = mac.to_hex();

        Ok(())
    }

    fn derive_key(&self, password: &str) -> Result<Vec<u8>> {
        let mut derived_key: Credential = [0u8; CREDENTIAL_LEN];
        self.kdf.derive_key(password.as_bytes(), &mut derived_key);
        Ok(derived_key.to_vec())
    }

    fn decrypt(&self, derived_key: &[u8]) -> Result<Vec<u8>> {
        let ciphertext: Vec<u8> = FromHex::from_hex(&self.ciphertext).expect("ciphertext");
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).expect("iv");
        decrypt(&ciphertext, derived_key, &iv)
    }

    fn encrypt(&self, derived_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).unwrap();
        encrypt(plaintext, derived_key, &iv)
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let derived_key_ret = self.derive_key(password);
        derived_key_ret.is_ok() && self.verify_derived_key(&derived_key_ret.expect(""))
    }

    pub fn verify_derived_key(&self, dk: &[u8]) -> bool {
        let cipher_bytes = Vec::from_hex(&self.ciphertext).expect("vec::from_hex");
        let mac = generate_mac(&dk, &cipher_bytes);
        self.mac == mac.to_hex()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kdf", content = "kdfparams")]
pub enum KdfType {
    #[serde(rename = "pbkdf2")]
    Pbkdf2(Pbkdf2Params),

    #[serde(rename = "scrypt")]
    Scrypt(SCryptParams),
}

impl Default for KdfType {
    fn default() -> Self {
        KdfType::Pbkdf2(Pbkdf2Params::default())
    }
}

impl KdfParams for KdfType {
    fn name(&self) -> &str {
        match self {
            KdfType::Pbkdf2(_) => "pbkdf2",
            KdfType::Scrypt(_) => "scrypt",
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            KdfType::Pbkdf2(pbkdf2) => pbkdf2.validate(),
            KdfType::Scrypt(scrypt) => scrypt.validate(),
        }
    }
    fn derive_key(&self, password: &[u8], out: &mut [u8]) {
        match self {
            KdfType::Pbkdf2(pbkdf2) => pbkdf2.derive_key(password, out),
            KdfType::Scrypt(scrypt) => scrypt.derive_key(password, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::_core::str::FromStr;
    use tcx_constants::TEST_PASSWORD;

    fn sample_json_str() -> &'static str {
        r#"
    {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "2cb9d4457b284e47877d08a5c9493b46"
    },
    "ciphertext": "17ff4858e697455f4966c6072473f3501534bc20deb339b58aeb8db0bd9fe91777148d0a909f679fb6e3a7a64609034afeb72a",
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 10240,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "37890eb305866aa07853d14e7666c2ed31e18efc1129f1c5a66b9cc93d03fd73"
    },
    "mac": "4906577f075ad714f328e7b33829fdccfa8cd22eab2c0a8bc4f577824188ed16"
  }"#
    }

    #[test]
    fn test_pbkdf2_params_default() {
        let param = Pbkdf2Params::default();
        let default = Pbkdf2Params {
            c: default_kdf_rounds(),
            prf: "hmac-sha256".to_owned(),
            dklen: 32,
            salt: "".to_owned(),
        };
        assert_eq!(default, param);
    }

    #[test]
    fn test_new_crypto() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        assert_ne!(crypto.ciphertext, "");
        assert_ne!(crypto.cipher, "");
        assert_ne!(crypto.mac, "");
        assert_ne!(crypto.cipherparams.iv, "");
        match &crypto.kdf {
            KdfType::Pbkdf2(params) => {
                assert_ne!(params.salt, "")
            }
            _ => panic!("kdf type must be pbkdf2"),
        }
        assert_eq!("pbkdf2", crypto.kdf.name());
    }

    #[test]
    fn test_decrypt_crypto() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        let cipher_bytes = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .plaintext()
            .unwrap();
        assert_eq!("TokenCoreX", String::from_utf8(cipher_bytes).unwrap());

        let ret = crypto.use_key(&Key::Password("WrongPassword".to_owned()));
        assert!(ret.is_err());
        let err = ret.err().unwrap();
        assert_eq!(
            Error::PasswordIncorrect,
            err.downcast::<crate::Error>().unwrap()
        );
    }

    #[test]
    fn test_enc_pair() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        let enc_pair = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .encrypt_with_random_iv("TokenCoreX".as_bytes())
            .unwrap();

        assert_ne!("", enc_pair.nonce);
        assert_ne!("", enc_pair.enc_str);

        let decrypted_bytes = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .decrypt_enc_pair(&enc_pair)
            .unwrap();
        let decrypted = String::from_utf8(decrypted_bytes).unwrap();

        assert_eq!("TokenCoreX", decrypted);

        let ret = crypto.use_key(&Key::Password("WrongPassword".to_owned()));
        assert!(ret.is_err());
        let err = ret.err().unwrap();
        assert_eq!(
            Error::PasswordIncorrect,
            err.downcast::<crate::Error>().unwrap()
        );
    }

    #[test]
    fn test_kdfparams_trait_validate() {
        let err = Pbkdf2Params::default().validate().err().unwrap();
        assert_eq!(
            err.downcast::<crate::Error>().unwrap(),
            Error::KdfParamsInvalid,
        );

        let mut params = Pbkdf2Params::default();
        params.salt = "0x1234".to_owned();

        assert!(params.validate().is_ok());

        let err = SCryptParams::default().validate().err().unwrap();
        assert_eq!(
            err.downcast::<crate::Error>().unwrap(),
            Error::KdfParamsInvalid
        );

        assert_eq!(*crate::KDF_ROUNDS.read() as u32, 262144);

        let v = env::var("KDF_ROUNDS");
        if v.is_ok() {
            let env_kdf_rounds = u32::from_str(&v.unwrap()).unwrap();
            env::remove_var("KDF_ROUNDS");
            assert_eq!(default_kdf_rounds(), 262144);
            env::set_var("KDF_ROUNDS", &env_kdf_rounds.to_string());
        } else {
            assert_eq!(default_kdf_rounds(), 262144);
        }
    }

    #[test]
    fn test_derive_key_pbkdf2() {
        let mut pbkdf2_param = Pbkdf2Params::default();
        pbkdf2_param.c = 1024;
        pbkdf2_param.salt = "01020304010203040102030401020304".to_string();
        let mut derived_key = [0; CREDENTIAL_LEN];
        pbkdf2_param.derive_key(TEST_PASSWORD.as_bytes(), &mut derived_key);
        let dk_hex = derived_key.to_hex();
        assert_eq!("515c00df30d4eb0e5662030ccea231301ce44d685eb29aca04469f4d6b701898e75e51080a482dd46c04cf39308e7d228a0f70a45d7fa17cd4027d04c39f5e17", dk_hex);
    }

    #[test]
    fn test_derive_key_scrypt() {
        let mut param = SCryptParams::default();
        param.n = 1024;
        param.salt = "01020304010203040102030401020304".to_string();
        let mut derived_key = [0; CREDENTIAL_LEN];
        param.derive_key(TEST_PASSWORD.as_bytes(), &mut derived_key);
        let dk_hex = derived_key.to_hex();
        assert_eq!("190fba2c4dcd250b67652b6ea401a286ba4afff692aa9700ce56edd5326cb23b05c9af493f8d3dccb8191437f8cb5d2c3ba718af64aee8a7f318eedf2af5eb3f", dk_hex);
    }

    #[test]
    fn test_decode_v3_keystore_crypto() {
        let data = r#"{
    "mac": "a10b412993ec783e854cb339b1f4165a013d41267adb561ed9ab47c209dea3ab",
    "cipherparams": {
      "iv": "799f757ee52b7c95aa76967fa908676c"
    },
    "kdfparams": {
      "dklen": 32,
      "r": 8,
      "salt": "e3fa7f40fecac7f6c61326dfb6aba4697c2daba9ecd41f017e996ae15aa18a51",
      "p": 1,
      "n": 1024
    },
    "cipher": "aes-128-ctr",
    "ciphertext": "d5c053f4893fbbaa0d58cc87d5b82abdbac55599a46fe6eb8e355487e5c4799039a4a4ae7f365db3d573946f3acb51a2cfb2aafe",
    "kdf": "scrypt"
  }"#;

        let crypto: Crypto = serde_json::from_str(data).unwrap();
        let result = crypto
            .use_key(&Key::Password("Insecure Pa55w0rd".to_owned()))
            .unwrap()
            .plaintext()
            .unwrap();
        let wif = String::from_utf8(result).unwrap();
        assert_eq!("L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB", wif)
    }

    #[test]
    fn test_deserialize_crypto_with_kdf_type_from_json() {
        let data = sample_json_str();
        let crypto: Crypto = serde_json::from_str(data).unwrap();

        assert_eq!(
            crypto.mac,
            "4906577f075ad714f328e7b33829fdccfa8cd22eab2c0a8bc4f577824188ed16"
        );
        assert_eq!(crypto.ciphertext, "17ff4858e697455f4966c6072473f3501534bc20deb339b58aeb8db0bd9fe91777148d0a909f679fb6e3a7a64609034afeb72a");
    }

    #[test]
    fn test_deserialize_from_json() {
        let data = sample_json_str();
        let crypto: Crypto = serde_json::from_str(data).unwrap();

        assert_eq!(
            crypto.mac,
            "4906577f075ad714f328e7b33829fdccfa8cd22eab2c0a8bc4f577824188ed16"
        );
        assert_eq!(crypto.ciphertext, "17ff4858e697455f4966c6072473f3501534bc20deb339b58aeb8db0bd9fe91777148d0a909f679fb6e3a7a64609034afeb72a");
    }

    #[test]
    fn test_cache_derived_key() {
        let cdk = CacheDerivedKey::new("12345678", &[1, 1, 1, 1]);
        let ret = cdk.get_derived_key("1234");
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

        let ret = cdk.get_derived_key("12345678").unwrap();
        assert_eq!(hex::encode(ret), "01010101");
    }
}
