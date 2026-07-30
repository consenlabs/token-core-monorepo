use crate::Error;
use crate::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::env;
use tcx_common::{random_u8_16, random_u8_32, FromHex, ToHex};
use tiny_keccak::Hasher;

const CREDENTIAL_LEN: usize = 64usize;
const KDF_SALT_MIN_LEN: usize = 16;
const KDF_SALT_MAX_LEN: usize = 64;
const PBKDF2_MAX_ROUNDS: u32 = 10_000_000;
const ARGON2ID_MEMORY_COST_KIB: u32 = 19 * 1024;
const ARGON2ID_TIME_COST: u32 = 2;
const ARGON2ID_PARALLELISM: u32 = 1;
const ARGON2ID_MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
const ARGON2ID_MAX_TIME_COST: u32 = 10;
const ARGON2ID_MAX_PARALLELISM: u32 = 16;
const SCRYPT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const SCRYPT_MAX_WORK_FACTOR: u64 = 1 << 22;
const SCRYPT_MAX_R: u32 = 32;
const SCRYPT_MAX_P: u32 = 16;

pub type Credential = [u8; CREDENTIAL_LEN];

fn default_kdf_rounds() -> u32 {
    env::var("KDF_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|rounds| (1..=PBKDF2_MAX_ROUNDS).contains(rounds))
        .or_else(|| {
            u32::try_from(*crate::KDF_ROUNDS.read())
                .ok()
                .filter(|rounds| (1..=PBKDF2_MAX_ROUNDS).contains(rounds))
        })
        .unwrap_or(600_000)
}

fn decode_kdf_salt(salt: &str) -> Result<Vec<u8>> {
    let salt = Vec::from_hex_auto(salt).map_err(|_| Error::KdfParamsInvalid)?;
    if !(KDF_SALT_MIN_LEN..=KDF_SALT_MAX_LEN).contains(&salt.len()) {
        return Err(Error::KdfParamsInvalid.into());
    }
    Ok(salt)
}

fn valid_dklen(dklen: u32) -> bool {
    dklen == 32 || dklen == CREDENTIAL_LEN as u32
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
    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()>;
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
        if !valid_dklen(self.dklen)
            || !(1..=PBKDF2_MAX_ROUNDS).contains(&self.c)
            || self.prf != "hmac-sha256"
        {
            return Err(Error::KdfParamsInvalid.into());
        }
        decode_kdf_salt(&self.salt).map(|_| ())
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        let salt_bytes = decode_kdf_salt(&self.salt)?;
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &salt_bytes, self.c, out)
            .map_err(|_| Error::KdfParamsInvalid.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Argon2idParams {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    dklen: u32,
    salt: String,
}

impl Default for Argon2idParams {
    fn default() -> Argon2idParams {
        Argon2idParams {
            memory_cost: ARGON2ID_MEMORY_COST_KIB,
            time_cost: ARGON2ID_TIME_COST,
            parallelism: ARGON2ID_PARALLELISM,
            dklen: CREDENTIAL_LEN as u32,
            salt: "".to_owned(),
        }
    }
}

impl KdfParams for Argon2idParams {
    fn name(&self) -> &str {
        "argon2id"
    }

    fn validate(&self) -> Result<()> {
        if !valid_dklen(self.dklen)
            || self.parallelism == 0
            || self.parallelism > ARGON2ID_MAX_PARALLELISM
            || self.time_cost == 0
            || self.time_cost > ARGON2ID_MAX_TIME_COST
            || self.memory_cost < 8 * self.parallelism
            || self.memory_cost > ARGON2ID_MAX_MEMORY_COST_KIB
        {
            return Err(Error::KdfParamsInvalid.into());
        }
        decode_kdf_salt(&self.salt).map(|_| ())
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        let salt_bytes = decode_kdf_salt(&self.salt)?;
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(out.len()),
        )
        .map_err(|_| Error::KdfParamsInvalid)?;

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, &salt_bytes, out)
            .map_err(|_| Error::KdfParamsInvalid.into())
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
        let memory_cost = 128u64
            .checked_mul(u64::from(self.n))
            .and_then(|value| value.checked_mul(u64::from(self.r)))
            .ok_or(Error::KdfParamsInvalid)?;
        let work_factor = u64::from(self.n)
            .checked_mul(u64::from(self.p))
            .ok_or(Error::KdfParamsInvalid)?;
        if !valid_dklen(self.dklen)
            || self.n < 2
            || !self.n.is_power_of_two()
            || self.r == 0
            || self.r > SCRYPT_MAX_R
            || self.p == 0
            || self.p > SCRYPT_MAX_P
            || memory_cost > SCRYPT_MAX_MEMORY_BYTES
            || work_factor > SCRYPT_MAX_WORK_FACTOR
        {
            return Err(Error::KdfParamsInvalid.into());
        }
        decode_kdf_salt(&self.salt).map(|_| ())
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        let salt_bytes = decode_kdf_salt(&self.salt)?;
        let log_n = self.n.trailing_zeros() as u8;
        let inner_params =
            scrypt::Params::new(log_n, self.r, self.p).map_err(|_| Error::KdfParamsInvalid)?;

        scrypt::scrypt(password, &salt_bytes, &inner_params, out)
            .map_err(|_| Error::KdfParamsInvalid.into())
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheDerivedKey {
    hashed_key: String,
    derived_key: Vec<u8>,
}

#[cfg(test)]
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
    let key = derived_key.get(..16).ok_or(Error::InvalidKeyIvLength)?;
    Ok(super::aes::ctr::encrypt_nopadding(plaintext, key, iv)?)
}

fn decrypt(ciphertext: &[u8], derived_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = derived_key.get(..16).ok_or(Error::InvalidKeyIvLength)?;
    Ok(super::aes::ctr::decrypt_nopadding(ciphertext, key, iv)?)
}

fn generate_mac(derived_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mac_key = derived_key.get(16..32).ok_or(Error::InvalidKeyIvLength)?;
    let result = [mac_key, ciphertext].concat();
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(result.as_slice());
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    Ok(output.to_vec())
}

fn encrypt_with_random_iv(derived_key: &[u8], plaintext: &[u8]) -> Result<EncPair> {
    let iv = random_u8_16();
    let ciphertext = encrypt(plaintext, derived_key, &iv)?;
    Ok(EncPair {
        enc_str: ciphertext.to_hex(),
        nonce: iv.to_hex(),
    })
}

fn decrypt_enc_pair(derived_key: &[u8], enc_pair: &EncPair) -> Result<Vec<u8>> {
    let ciphertext = Vec::from_hex_auto(&enc_pair.enc_str).map_err(|_| Error::InvalidCiphertext)?;
    let iv = Vec::from_hex_auto(&enc_pair.nonce).map_err(|_| Error::InvalidKeyIvLength)?;

    decrypt(&ciphertext, derived_key, &iv)
}

impl<'a> Unlocker<'a> {
    pub fn derived_key(&self) -> &[u8] {
        &self.derived_key
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
    pub fn use_key(&self, key: &Key) -> Result<Unlocker<'_>> {
        match key {
            Key::Password(password) => {
                let derived_key = self.derive_key(password)?;
                if !self.mac.is_empty() && !self.verify_derived_key(&derived_key) {
                    return Err(Error::PasswordIncorrect.into());
                }

                Ok(Unlocker {
                    crypto: self,
                    derived_key,
                })
            }
            Key::DerivedKey(derived_key_hex) => {
                let derived_key = Vec::from_hex_auto(derived_key_hex)?;
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
        let param = Argon2idParams {
            salt: random_u8_32().to_hex(),
            ..Argon2idParams::default()
        };

        Self::new_with_kdf(password, origin, KdfType::Argon2id(param))
    }

    pub fn new_with_kdf(password: &str, plaintext: &[u8], kdf: KdfType) -> Crypto {
        let iv = random_u8_16();

        let mut crypto = Crypto {
            cipher: "aes-128-ctr".to_owned(),
            cipherparams: CipherParams { iv: iv.to_hex() },
            ciphertext: String::from(""),
            kdf,
            mac: String::from(""),
        };

        let derived_key = crypto.derive_key(password).expect("derive key");
        let ciphertext = crypto.encrypt(&derived_key, plaintext).expect("encrypt");
        let mac =
            generate_mac(&derived_key, &ciphertext).expect("generated credential is 64 bytes");

        crypto.ciphertext = ciphertext.to_hex();
        crypto.mac = mac.to_hex();

        crypto
    }

    /*
     * Used to update the ciphertext without changing the derived key.
     * A fresh IV is required because AES-CTR must never reuse the same
     * key/IV pair for different plaintexts.
     */
    pub fn dangerous_rewrite_plaintext(
        &mut self,
        derived_key: &[u8],
        plaintext: &[u8],
    ) -> Result<()> {
        let iv = random_u8_16();
        let ciphertext = encrypt(plaintext, derived_key, &iv)?;
        let mac = generate_mac(derived_key, &ciphertext)?;

        self.cipherparams.iv = iv.to_hex();
        self.ciphertext = ciphertext.to_hex();
        self.mac = mac.to_hex();

        Ok(())
    }

    fn derive_key(&self, password: &str) -> Result<Vec<u8>> {
        let mut derived_key: Credential = [0u8; CREDENTIAL_LEN];
        self.kdf.validate()?;
        self.kdf.derive_key(password.as_bytes(), &mut derived_key)?;

        Ok(derived_key.to_vec())
    }

    fn decrypt(&self, derived_key: &[u8]) -> Result<Vec<u8>> {
        let ciphertext =
            Vec::from_hex_auto(&self.ciphertext).map_err(|_| Error::InvalidCiphertext)?;
        let iv =
            Vec::from_hex_auto(&self.cipherparams.iv).map_err(|_| Error::InvalidKeyIvLength)?;
        decrypt(&ciphertext, derived_key, &iv)
    }

    fn encrypt(&self, derived_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv =
            Vec::from_hex_auto(&self.cipherparams.iv).map_err(|_| Error::InvalidKeyIvLength)?;
        encrypt(plaintext, derived_key, &iv)
    }

    pub fn verify_password(&self, password: &str) -> bool {
        self.derive_key(password)
            .map(|derived_key| self.verify_derived_key(&derived_key))
            .unwrap_or(false)
    }

    pub fn verify_derived_key(&self, dk: &[u8]) -> bool {
        Vec::from_hex_auto(&self.ciphertext)
            .ok()
            .and_then(|ciphertext| generate_mac(dk, &ciphertext).ok())
            .map(|mac| self.mac == mac.to_hex())
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kdf", content = "kdfparams")]
pub enum KdfType {
    #[serde(rename = "argon2id")]
    Argon2id(Argon2idParams),

    #[serde(rename = "pbkdf2")]
    Pbkdf2(Pbkdf2Params),

    #[serde(rename = "scrypt")]
    Scrypt(SCryptParams),
}

impl Default for KdfType {
    fn default() -> Self {
        KdfType::Argon2id(Argon2idParams::default())
    }
}

impl KdfParams for KdfType {
    fn name(&self) -> &str {
        match self {
            KdfType::Argon2id(_) => "argon2id",
            KdfType::Pbkdf2(_) => "pbkdf2",
            KdfType::Scrypt(_) => "scrypt",
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            KdfType::Argon2id(argon2id) => argon2id.validate(),
            KdfType::Pbkdf2(pbkdf2) => pbkdf2.validate(),
            KdfType::Scrypt(scrypt) => scrypt.validate(),
        }
    }
    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        match self {
            KdfType::Argon2id(argon2id) => argon2id.derive_key(password, out),
            KdfType::Pbkdf2(pbkdf2) => pbkdf2.derive_key(password, out),
            KdfType::Scrypt(scrypt) => scrypt.derive_key(password, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::{Duration, Instant};
    use tcx_common::random_u8_64;
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
            KdfType::Argon2id(params) => {
                assert_ne!(params.salt, "")
            }
            _ => panic!("kdf type must be argon2id"),
        }
        assert_eq!("argon2id", crypto.kdf.name());
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
    fn test_kdf_type() {
        let params = Argon2idParams {
            salt: random_u8_32().to_hex(),
            ..Default::default()
        };

        let kdf_type = KdfType::Argon2id(params);
        assert!(kdf_type.validate().is_ok());
        assert_eq!(kdf_type.name(), "argon2id");

        let params = Pbkdf2Params {
            salt: random_u8_32().to_hex(),
            ..Default::default()
        };

        let kdf_type = KdfType::Pbkdf2(params);
        assert!(kdf_type.validate().is_ok());
        assert_eq!(kdf_type.name(), "pbkdf2");

        let params = SCryptParams {
            salt: random_u8_32().to_hex(),
            ..Default::default()
        };

        let kdf_type = KdfType::Scrypt(params);
        assert!(kdf_type.validate().is_ok());
        assert_eq!(kdf_type.name(), "scrypt");

        let kdf_type = KdfType::default();
        assert_eq!(kdf_type.name(), "argon2id");
    }

    #[test]
    fn test_verify_password() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        assert!(crypto.verify_password(TEST_PASSWORD));
        assert!(!crypto.verify_password("WrongPassword"));
    }

    #[test]
    fn test_dangerous_rewrite_plaintext() {
        let mut crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        let original_iv = crypto.cipherparams.iv.clone();
        let derived_key = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .derived_key()
            .to_vec();
        crypto
            .dangerous_rewrite_plaintext(&derived_key, "RewrittenTokenCoreX".as_bytes())
            .unwrap();
        let cipher_bytes = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .plaintext()
            .unwrap();
        assert_eq!(
            "RewrittenTokenCoreX",
            String::from_utf8(cipher_bytes).unwrap()
        );
        assert_ne!(original_iv, crypto.cipherparams.iv);
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
        let err = Argon2idParams::default().validate().err().unwrap();
        assert_eq!(
            err.downcast::<crate::Error>().unwrap(),
            Error::KdfParamsInvalid,
        );

        let params = Argon2idParams {
            salt: "0x01020304010203040102030401020304".to_owned(),
            ..Default::default()
        };

        assert!(params.validate().is_ok());
        assert_eq!(params.name(), "argon2id");

        let err = Pbkdf2Params::default().validate().err().unwrap();
        assert_eq!(
            err.downcast::<crate::Error>().unwrap(),
            Error::KdfParamsInvalid,
        );

        let params = Pbkdf2Params {
            salt: "0x01020304010203040102030401020304".to_owned(),
            ..Default::default()
        };

        assert!(params.validate().is_ok());
        assert_eq!(params.name(), "pbkdf2");

        let err = SCryptParams::default().validate().err().unwrap();
        assert_eq!(
            err.downcast::<crate::Error>().unwrap(),
            Error::KdfParamsInvalid
        );

        assert_eq!(*crate::KDF_ROUNDS.read() as u32, 600000);

        if let Ok(v) = env::var("KDF_ROUNDS") {
            let env_kdf_rounds = u32::from_str(&v).unwrap();
            env::remove_var("KDF_ROUNDS");
            assert_eq!(default_kdf_rounds(), 600000);
            env::set_var("KDF_ROUNDS", env_kdf_rounds.to_string());
        } else {
            assert_eq!(default_kdf_rounds(), 600000);
        }
    }

    #[test]
    fn test_derive_key_pbkdf2() {
        let mut pbkdf2_param = Pbkdf2Params {
            c: 1024,
            salt: "01020304010203040102030401020304".to_string(),
            ..Default::default()
        };
        let mut derived_key = [0; CREDENTIAL_LEN];
        pbkdf2_param
            .derive_key(TEST_PASSWORD.as_bytes(), &mut derived_key)
            .unwrap();
        let dk_hex = derived_key.to_hex();
        assert_eq!("515c00df30d4eb0e5662030ccea231301ce44d685eb29aca04469f4d6b701898e75e51080a482dd46c04cf39308e7d228a0f70a45d7fa17cd4027d04c39f5e17", dk_hex);

        assert!(pbkdf2_param.validate().is_ok());
        pbkdf2_param.c = 0;
        assert!(pbkdf2_param.validate().is_err());
    }

    #[test]
    fn test_derive_key_argon2id() {
        let mut param = Argon2idParams {
            memory_cost: 32,
            time_cost: 2,
            parallelism: 1,
            salt: "01020304010203040102030401020304".to_string(),
            ..Default::default()
        };
        let mut derived_key = [0; CREDENTIAL_LEN];
        param
            .derive_key(TEST_PASSWORD.as_bytes(), &mut derived_key)
            .unwrap();
        let dk_hex = derived_key.to_hex();
        assert_eq!("d588733f0b9f482908fd7a2f9d48d61c40b01df8016b2ee3b10a51296d7b4e873d0ae92772dd94cce9d1c2ddfbb97fb25b7a66208713313fc04479712086db30", dk_hex);
        assert_eq!("argon2id", param.name());

        assert!(param.validate().is_ok());
        param.memory_cost = 0;
        assert!(param.validate().is_err());
    }

    #[test]
    fn test_derive_key_scrypt() {
        let mut param = SCryptParams {
            n: 1024,
            salt: "01020304010203040102030401020304".to_string(),
            ..Default::default()
        };
        let mut derived_key = [0; CREDENTIAL_LEN];
        param
            .derive_key(TEST_PASSWORD.as_bytes(), &mut derived_key)
            .unwrap();
        let dk_hex = derived_key.to_hex();
        assert_eq!("190fba2c4dcd250b67652b6ea401a286ba4afff692aa9700ce56edd5326cb23b05c9af493f8d3dccb8191437f8cb5d2c3ba718af64aee8a7f318eedf2af5eb3f", dk_hex);
        assert_eq!("scrypt", param.name());

        assert!(param.validate().is_ok());
        param.n = 0;
        assert!(param.validate().is_err());
    }

    #[test]
    fn rejects_untrusted_kdf_resource_exhaustion_params() {
        let salt = "01020304010203040102030401020304".to_owned();

        let pbkdf2 = Pbkdf2Params {
            c: PBKDF2_MAX_ROUNDS + 1,
            salt: salt.clone(),
            ..Default::default()
        };
        assert_eq!(
            pbkdf2.validate().unwrap_err().downcast::<Error>().unwrap(),
            Error::KdfParamsInvalid
        );

        let argon2id = Argon2idParams {
            memory_cost: ARGON2ID_MAX_MEMORY_COST_KIB + 1,
            salt: salt.clone(),
            ..Default::default()
        };
        assert_eq!(
            argon2id
                .validate()
                .unwrap_err()
                .downcast::<Error>()
                .unwrap(),
            Error::KdfParamsInvalid
        );

        let scrypt = SCryptParams {
            n: 1 << 20,
            r: 8,
            salt,
            ..Default::default()
        };
        assert_eq!(
            scrypt.validate().unwrap_err().downcast::<Error>().unwrap(),
            Error::KdfParamsInvalid
        );
    }

    #[test]
    fn malformed_imported_crypto_returns_errors_instead_of_panicking() {
        let mut crypto: Crypto = serde_json::from_str(sample_json_str()).unwrap();
        if let KdfType::Pbkdf2(params) = &mut crypto.kdf {
            params.salt = "not-hex".to_owned();
        }
        let error = match crypto.use_key(&Key::Password(TEST_PASSWORD.to_owned())) {
            Ok(_) => panic!("malformed KDF salt must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.downcast::<Error>().unwrap(), Error::KdfParamsInvalid);

        let mut crypto: Crypto = serde_json::from_str(sample_json_str()).unwrap();
        crypto.ciphertext = "not-hex".to_owned();
        assert!(!crypto.verify_derived_key(&[0u8; CREDENTIAL_LEN]));
        assert!(!crypto.verify_password(TEST_PASSWORD));
    }

    fn profile_kdf<F>(name: &str, mut f: F) -> Duration
    where
        F: FnMut(),
    {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed();
        eprintln!("{name}: {} ms", elapsed.as_millis());
        elapsed
    }

    #[test]
    #[ignore]
    fn test_kdf_profile() {
        let password = TEST_PASSWORD.as_bytes();
        let salt = "01020304010203040102030401020304".to_string();
        let mut derived_key = [0; CREDENTIAL_LEN];

        let argon2id = Argon2idParams {
            salt: salt.clone(),
            ..Default::default()
        };
        let argon2id_elapsed = profile_kdf("argon2id m=19456KiB t=2 p=1", || {
            argon2id.derive_key(password, &mut derived_key).unwrap()
        });

        let scrypt = SCryptParams {
            n: 1 << 17,
            salt: salt.clone(),
            ..Default::default()
        };
        let scrypt_elapsed = profile_kdf("scrypt n=2^17 r=8 p=1", || {
            scrypt.derive_key(password, &mut derived_key).unwrap()
        });

        let pbkdf2 = Pbkdf2Params {
            c: 600000,
            salt,
            ..Default::default()
        };
        let pbkdf2_elapsed = profile_kdf("pbkdf2-hmac-sha256 c=600000", || {
            pbkdf2.derive_key(password, &mut derived_key).unwrap()
        });

        assert!(argon2id_elapsed.as_nanos() > 0);
        assert!(scrypt_elapsed.as_nanos() > 0);
        assert!(pbkdf2_elapsed.as_nanos() > 0);
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
    fn test_use_derive_key() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        let derived_key = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .derived_key()
            .to_hex();

        let u = crypto.use_key(&Key::DerivedKey(derived_key)).unwrap();
        assert_eq!(
            "TokenCoreX",
            String::from_utf8(u.plaintext().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_use_wrong_derived_key() {
        let crypto: Crypto = Crypto::new(TEST_PASSWORD, "TokenCoreX".as_bytes());
        let wrong_derive_key = random_u8_64().to_hex();
        let u = crypto.use_key(&Key::DerivedKey(wrong_derive_key));
        assert!(u.is_err());
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
