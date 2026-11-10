use crate::Error;
use crate::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::env;
use tcx_common::{random_u8_16, random_u8_32, FromHex, ToHex};
use tiny_keccak::Hasher;

const CREDENTIAL_LEN: usize = 64usize;
const ARGON2ID_MEMORY_COST_KIB: u32 = 19 * 1024;
const ARGON2ID_TIME_COST: u32 = 2;
const ARGON2ID_PARALLELISM: u32 = 1;
const ARGON2ID_MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
const ARGON2ID_MAX_TIME_COST: u32 = 10;
const ARGON2ID_MAX_PARALLELISM: u32 = 16;
const ARGON2ID_SALT_MIN_LEN: usize = 16;
const ARGON2ID_SALT_MAX_LEN: usize = 64;

pub type Credential = [u8; CREDENTIAL_LEN];

fn default_kdf_rounds() -> u32 {
    let v = env::var("KDF_ROUNDS");
    if let Ok(v) = v {
        v.parse::<u32>().unwrap()
    } else {
        *crate::KDF_ROUNDS.read() as u32
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
        if self.dklen == 0 || self.c == 0 || self.salt.is_empty() || self.prf.is_empty() {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        let salt_bytes = Vec::from_hex(&self.salt).map_err(|_| Error::KdfParamsInvalid)?;
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

impl Argon2idParams {
    fn salt_bytes(&self) -> Result<Vec<u8>> {
        // Bound the encoded length before allocating for untrusted JSON input.
        if self.salt.len() > ARGON2ID_SALT_MAX_LEN * 2 + 2 {
            return Err(Error::KdfParamsInvalid.into());
        }
        let salt = Vec::from_hex_auto(&self.salt).map_err(|_| Error::KdfParamsInvalid)?;
        if !(ARGON2ID_SALT_MIN_LEN..=ARGON2ID_SALT_MAX_LEN).contains(&salt.len()) {
            return Err(Error::KdfParamsInvalid.into());
        }
        Ok(salt)
    }
}

impl KdfParams for Argon2idParams {
    fn name(&self) -> &str {
        "argon2id"
    }

    fn validate(&self) -> Result<()> {
        if !matches!(self.dklen, 32 | 64)
            || self.parallelism == 0
            || self.parallelism > ARGON2ID_MAX_PARALLELISM
            || self.time_cost == 0
            || self.time_cost > ARGON2ID_MAX_TIME_COST
            || self.memory_cost < 8 * self.parallelism
            || self.memory_cost > ARGON2ID_MAX_MEMORY_COST_KIB
        {
            return Err(Error::KdfParamsInvalid.into());
        }
        self.salt_bytes().map(|_| ())
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        if out.len() != self.dklen as usize {
            return Err(Error::KdfParamsInvalid.into());
        }
        let salt_bytes = self.salt_bytes()?;
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(self.dklen as usize),
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
        if self.dklen == 0 || self.n == 0 || self.salt.is_empty() || self.p == 0 || self.r == 0 {
            Err(Error::KdfParamsInvalid.into())
        } else {
            Ok(())
        }
    }

    fn derive_key(&self, password: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        let salt_bytes = Vec::from_hex(&self.salt).map_err(|_| Error::KdfParamsInvalid)?;
        let log_n = (self.n as f64).log2().round();
        let inner_params = scrypt::Params::new(log_n as u8, self.r, self.p)
            .map_err(|_| Error::KdfParamsInvalid)?;

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
    let key = &derived_key[0..16];
    super::aes::ctr::encrypt_nopadding(plaintext, key, iv)
}

fn decrypt(ciphertext: &[u8], derived_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = &derived_key[0..16];
    super::aes::ctr::decrypt_nopadding(ciphertext, key, iv)
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
    let iv = random_u8_16();
    let ciphertext = encrypt(plaintext, derived_key, &iv)?;
    Ok(EncPair {
        enc_str: ciphertext.to_hex(),
        nonce: iv.to_hex(),
    })
}

fn decrypt_enc_pair(derived_key: &[u8], enc_pair: &EncPair) -> Result<Vec<u8>> {
    let ciphertext: Vec<u8> = Vec::from_hex(&enc_pair.enc_str).unwrap();
    let iv: Vec<u8> = Vec::from_hex(&enc_pair.nonce).unwrap();

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

        Self::try_new_with_kdf(password, origin, KdfType::Argon2id(param))
            .expect("valid default argon2id parameters")
    }

    pub fn new_v3(password: &str, origin: &[u8]) -> Result<Crypto> {
        let param = Pbkdf2Params {
            salt: random_u8_32().to_hex(),
            ..Pbkdf2Params::default()
        };
        Self::try_new_with_kdf(password, origin, KdfType::Pbkdf2(param))
    }

    /// Compatibility constructor for trusted, valid parameters only.
    /// Use `try_new_with_kdf` for caller-supplied or deserialized parameters.
    ///
    /// # Panics
    /// Panics if the trusted parameters are invalid. Untrusted input must use
    /// `try_new_with_kdf`, which returns `kdf_params_invalid` instead.
    pub fn new_with_kdf(password: &str, plaintext: &[u8], kdf: KdfType) -> Crypto {
        Self::try_new_with_kdf(password, plaintext, kdf)
            .expect("new_with_kdf requires trusted valid parameters; use try_new_with_kdf")
    }

    pub fn try_new_with_kdf(password: &str, plaintext: &[u8], kdf: KdfType) -> Result<Crypto> {
        let iv = random_u8_16();

        let mut crypto = Crypto {
            cipher: "aes-128-ctr".to_owned(),
            cipherparams: CipherParams { iv: iv.to_hex() },
            ciphertext: String::from(""),
            kdf,
            mac: String::from(""),
        };

        let derived_key = crypto.derive_key(password)?;
        let ciphertext = crypto.encrypt(&derived_key, plaintext)?;
        let mac = generate_mac(&derived_key, &ciphertext);

        crypto.ciphertext = ciphertext.to_hex();
        crypto.mac = mac.to_hex();

        Ok(crypto)
    }

    /*
     * used to update the ciphertext, but without changing the the derived key.
     */
    pub fn dangerous_rewrite_plaintext(
        &mut self,
        derived_key: &[u8],
        plaintext: &[u8],
    ) -> Result<()> {
        let ciphertext = self.encrypt(derived_key, plaintext).expect("encrypt");
        let mac = generate_mac(derived_key, &ciphertext);

        self.ciphertext = ciphertext.to_hex();
        self.mac = mac.to_hex();

        Ok(())
    }

    fn derive_key(&self, password: &str) -> Result<Vec<u8>> {
        self.kdf.validate()?;
        // PBKDF2/scrypt historically expose 64 bytes even for V3 dklen=32.
        // Their prefixes are length-independent; Argon2's output is not.
        let dklen = match &self.kdf {
            KdfType::Argon2id(params) => params.dklen as usize,
            _ => CREDENTIAL_LEN,
        };
        let mut derived_key = vec![0u8; dklen];
        self.kdf.derive_key(password.as_bytes(), &mut derived_key)?;

        Ok(derived_key)
    }

    fn decrypt(&self, derived_key: &[u8]) -> Result<Vec<u8>> {
        let ciphertext: Vec<u8> = FromHex::from_hex(&self.ciphertext).expect("ciphertext");
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).expect("iv");
        decrypt(&ciphertext, derived_key, &iv)
    }

    fn encrypt(&self, derived_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv: Vec<u8> = Vec::from_hex(&self.cipherparams.iv).unwrap();
        encrypt(plaintext, derived_key, &iv)
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let derived_key_ret = self.derive_key(password);
        derived_key_ret.is_ok() && self.verify_derived_key(&derived_key_ret.expect(""))
    }

    pub fn verify_derived_key(&self, dk: &[u8]) -> bool {
        let cipher_bytes = Vec::from_hex(&self.ciphertext).expect("vec::from_hex");
        let mac = generate_mac(dk, &cipher_bytes);
        self.mac == mac.to_hex()
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
        assert_eq!(crypto.derive_key(TEST_PASSWORD).unwrap().len(), 64);
    }

    #[test]
    fn test_new_v3_uses_standard_pbkdf2() {
        let crypto = Crypto::new_v3(TEST_PASSWORD, b"TokenCoreX").unwrap();
        let json = serde_json::to_value(&crypto).unwrap();
        assert_eq!(json["kdf"], "pbkdf2");
        assert_eq!(json["kdfparams"]["dklen"], 32);
        assert_eq!(json["kdfparams"]["prf"], "hmac-sha256");

        // A standard V3 reader derives only the recorded 32 bytes.
        let params = match &crypto.kdf {
            KdfType::Pbkdf2(params) => params,
            _ => panic!("V3 must use PBKDF2"),
        };
        let mut dk = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            TEST_PASSWORD.as_bytes(),
            &Vec::from_hex(&params.salt).unwrap(),
            params.c,
            &mut dk,
        )
        .unwrap();
        assert!(crypto.verify_derived_key(&dk));
        assert_eq!(crypto.decrypt(&dk).unwrap(), b"TokenCoreX");
    }

    fn constant_crypto(kdf: &str, params: serde_json::Value, ct: &str, mac: &str) -> Crypto {
        serde_json::from_value(serde_json::json!({
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "000102030405060708090a0b0c0d0e0f"},
            "ciphertext": ct,
            "kdf": kdf,
            "kdfparams": params,
            "mac": mac,
        }))
        .unwrap()
    }

    #[test]
    fn test_argon2id_constant_vectors() {
        // KDF/AES constants generated independently with Python cryptography/OpenSSL.
        let vectors = [
            (32, "d956f86a8815a4ee7eacd92712ed85b204d935c81a216bdd9a88863522045f88",
             "92fccf00c2a20bda45b9", "8b29d9dad825838510fb0a117145683aba42793e7101b6476c27fa4528c733de"),
            (64, "d588733f0b9f482908fd7a2f9d48d61c40b01df8016b2ee3b10a51296d7b4e873d0ae92772dd94cce9d1c2ddfbb97fb25b7a66208713313fc04479712086db30",
             "30e3f26d21a778cb7a8a", "9e3e1b00db14da4960d7714cc7d07f8f0859ca21a9d604e7513fcc64442f931f"),
        ];
        for (dklen, dk, ct, mac) in vectors {
            let crypto = constant_crypto(
                "argon2id",
                serde_json::json!({
                    "memoryCost": 32, "timeCost": 2, "parallelism": 1, "dklen": dklen,
                    "salt": "01020304010203040102030401020304",
                }),
                ct,
                mac,
            );
            let unlocker = crypto
                .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
                .unwrap();
            assert_eq!(unlocker.derived_key().len(), dklen);
            assert_eq!(unlocker.derived_key().to_hex(), dk);
            assert_eq!(unlocker.plaintext().unwrap(), b"TokenCoreX");
            assert!(crypto.verify_password(TEST_PASSWORD));
            assert_eq!(
                crypto
                    .use_key(&Key::Password("wrong".into()))
                    .err()
                    .unwrap()
                    .to_string(),
                "password_incorrect"
            );
            assert_eq!(
                crypto
                    .use_key(&Key::DerivedKey(dk.into()))
                    .unwrap()
                    .plaintext()
                    .unwrap(),
                b"TokenCoreX"
            );

            let decoded: Crypto =
                serde_json::from_str(&serde_json::to_string(&crypto).unwrap()).unwrap();
            assert_eq!(decoded.derive_key(TEST_PASSWORD).unwrap().to_hex(), dk);
        }
    }

    #[test]
    fn test_legacy_kdf_constant_vectors() {
        // Python hashlib + cryptography/OpenSSL; keep the historical 64-byte credential.
        let vectors = [
            ("pbkdf2", serde_json::json!({"c": 1024, "prf": "hmac-sha256"}),
             "515c00df30d4eb0e5662030ccea231301ce44d685eb29aca04469f4d6b701898e75e51080a482dd46c04cf39308e7d228a0f70a45d7fa17cd4027d04c39f5e17",
             "02f6d21f07206a9b0089", "48adc2daf71d6287a9bd9fad3ddb3ada7bed0845555d9d606b94bf8518e58dd3"),
            ("scrypt", serde_json::json!({"n": 1024, "r": 8, "p": 1}),
             "190fba2c4dcd250b67652b6ea401a286ba4afff692aa9700ce56edd5326cb23b05c9af493f8d3dccb8191437f8cb5d2c3ba718af64aee8a7f318eedf2af5eb3f",
             "671115873d92c1c85706", "29501a8a5f362b99cf191bfcc09cfb3cdd5d8e493cf77ee58beff80a715e0c82"),
        ];
        for (name, mut params, dk, ct, mac) in vectors {
            params["salt"] = "01020304010203040102030401020304".into();
            for dklen in [32, 64] {
                params["dklen"] = dklen.into();
                let crypto = constant_crypto(name, params.clone(), ct, mac);
                let unlocker = crypto
                    .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
                    .unwrap();
                assert_eq!(unlocker.derived_key().to_hex(), dk);
                assert_eq!(unlocker.plaintext().unwrap(), b"TokenCoreX");
                assert!(crypto.verify_derived_key(&Vec::from_hex(&dk[..64]).unwrap()));
            }
        }
    }

    #[test]
    fn test_argon2id_rejects_invalid_params_without_panicking() {
        let valid = serde_json::json!({
            "memoryCost": 32, "timeCost": 2, "parallelism": 1, "dklen": 64,
            "salt": "01020304010203040102030401020304",
        });
        let cases = [
            ("dklen", serde_json::json!(0)),
            ("dklen", serde_json::json!(31)),
            ("dklen", serde_json::json!(33)),
            ("dklen", serde_json::json!(65)),
            ("dklen", serde_json::json!(u32::MAX)),
            ("memoryCost", serde_json::json!(0)),
            ("memoryCost", serde_json::json!(7)),
            (
                "memoryCost",
                serde_json::json!(ARGON2ID_MAX_MEMORY_COST_KIB + 1),
            ),
            ("memoryCost", serde_json::json!(u32::MAX)),
            ("timeCost", serde_json::json!(0)),
            ("timeCost", serde_json::json!(ARGON2ID_MAX_TIME_COST + 1)),
            ("parallelism", serde_json::json!(0)),
            ("parallelism", serde_json::json!(5)), // memory < 8 * parallelism
            (
                "parallelism",
                serde_json::json!(ARGON2ID_MAX_PARALLELISM + 1),
            ),
            ("parallelism", serde_json::json!(u32::MAX)),
            ("salt", serde_json::json!("")),
            ("salt", serde_json::json!("0x1234")),
            ("salt", serde_json::json!("gg".repeat(16))),
            ("salt", serde_json::json!("a".repeat(33))),
            ("salt", serde_json::json!("ab".repeat(15))),
            ("salt", serde_json::json!("ab".repeat(65))),
        ];
        for (field, value) in cases {
            let mut params = valid.clone();
            params[field] = value;
            let crypto = constant_crypto("argon2id", params.clone(), "00", "00");
            let err = crypto
                .use_key(&Key::Password(TEST_PASSWORD.into()))
                .err()
                .unwrap();
            assert_eq!(err.to_string(), "kdf_params_invalid", "{params}");
            assert!(!crypto.verify_password(TEST_PASSWORD));
            let kdf: Argon2idParams = serde_json::from_value(params).unwrap();
            let mut out = [0u8; 64];
            assert_eq!(
                kdf.derive_key(b"password", &mut out)
                    .unwrap_err()
                    .to_string(),
                "kdf_params_invalid"
            );
            assert_eq!(
                Crypto::try_new_with_kdf("password", b"plaintext", KdfType::Argon2id(kdf))
                    .unwrap_err()
                    .to_string(),
                "kdf_params_invalid"
            );
        }

        let params: Argon2idParams = serde_json::from_value(valid).unwrap();
        assert!(params.derive_key(b"password", &mut [0u8; 32]).is_err());
        for salt_len in [16, 64] {
            for dklen in [32, 64] {
                let params = Argon2idParams {
                    memory_cost: ARGON2ID_MAX_MEMORY_COST_KIB,
                    time_cost: ARGON2ID_MAX_TIME_COST,
                    parallelism: ARGON2ID_MAX_PARALLELISM,
                    dklen,
                    salt: format!("0x{}", "ab".repeat(salt_len)),
                };
                assert!(params.validate().is_ok());
            }
        }
        let params = Argon2idParams {
            memory_cost: 16,
            parallelism: 2,
            salt: "ab".repeat(16),
            ..Default::default()
        };
        assert!(params.derive_key(b"password", &mut [0u8; 64]).is_ok());
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
        let derived_key = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .derived_key()
            .to_vec();
        crypto
            .dangerous_rewrite_plaintext(&derived_key, "TokenCoreX".as_bytes())
            .unwrap();
        let cipher_bytes = crypto
            .use_key(&Key::Password(TEST_PASSWORD.to_owned()))
            .unwrap()
            .plaintext()
            .unwrap();
        assert_eq!("TokenCoreX", String::from_utf8(cipher_bytes).unwrap());
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
            salt: "0x1234".to_owned(),
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
