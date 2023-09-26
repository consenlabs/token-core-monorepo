// use crate::constants::{CHAIN_TYPE_ETHEREUM, ETHEREUM_PATH};
// use crate::imt_keystore::{IMTKeystore, WALLETS, WALLET_KEYSTORE_DIR};
// use crate::model::{Metadata, FROM_NEW_IDENTITY, FROM_RECOVERED_IDENTITY};
// use crate::wallet_api::{CreateIdentityParam, RecoverIdentityParam};
use crate::Error;
use crate::Result;
use bip39::{Language, Mnemonic, Seed};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::network::constants::Network;
use bitcoin::util::base58;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::key::PrivateKey;
use bitcoin::VarInt;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac_sha256::HMAC;
use lazy_static::lazy_static;
use multihash::{Code, MultihashDigest};
use parking_lot::RwLock;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tcx_common::{keccak256, merkle_hash, random_u8_16, sha256, unix_timestamp};
use tcx_crypto::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use tcx_crypto::crypto::Unlocker;
use tcx_crypto::{Crypto, EncPair, Key};
use tcx_primitive::{PrivateKey as TraitPrivateKey, Secp256k1PrivateKey};
use uuid::Uuid;

// lazy_static! {
//     pub static ref IDENTITY_KEYSTORE: RwLock<IdentityKeystore> =
//         RwLock::new(IdentityKeystore::default());
// }

pub const IDENTITY_KEYSTORE_FILE_NAME: &'static str = "identity.json";
pub const VERSION: u32 = 1000;

// #[derive(Debug, Deserialize, Serialize, Clone, Default)]
// #[serde(rename_all = "camelCase")]
// pub struct IdentityKeystore {
//     pub crypto: Crypto,
//     pub id: String,
//     pub version: u32,
//     pub enc_auth_key: EncPair,
//     pub enc_key: String,
//     pub enc_mnemonic: EncPair,
//     pub identifier: String,
//     pub ipfs_id: String,
//     #[serde(rename = "walletIDs")]
//     pub wallet_ids: Vec<String>,
//     pub im_token_meta: Metadata,
// }

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub enc_auth_key: EncPair,
    pub enc_key: String,
    pub identifier: String,
    pub ipfs_id: String,
}

impl Identity {
    pub fn new(mnemonic_phrase: &str, unlocker: &Unlocker) -> Result<Self> {
        let network_type = Network::Bitcoin;

        let validate_result = Mnemonic::validate(mnemonic_phrase, Language::English);
        if validate_result.is_err() {
            return Err(Error::InvalidMnemonic.into());
        }
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let master_key = ExtendedPrivKey::new_master(network_type, seed.as_ref())?;

        let salt = "Automatic Backup Key Mainnet";

        let backup_key = HMAC::mac(salt.as_bytes(), master_key.private_key.secret_bytes());

        let authentication_key = HMAC::mac("Authentication Key".as_bytes(), backup_key);

        let auth_private_key = PrivateKey::from_slice(authentication_key.as_ref(), network_type)?;
        let secp = Secp256k1::new();
        let auth_pubkey_hash = auth_private_key.public_key(&secp).pubkey_hash();

        let network_header = 0;

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

        // let mut crypto: Crypto = Crypto::new(password, master_prikey_bytes.as_bytes());
        // let unlocker = crypto.use_key(&Key::Password(password.to_string()))?;

        let enc_auth_key = unlocker.encrypt_with_random_iv(authentication_key.as_slice())?;
        let enc_mnemonic = unlocker.encrypt_with_random_iv(mnemonic.phrase().as_bytes())?;

        // let identity_keystore = IdentityKeystore {
        //     crypto,
        //     id: Uuid::new_v4().as_hyphenated().to_string(),
        //     version: VERSION,
        //     enc_auth_key,
        //     enc_key: hex::encode(enc_key_bytes),
        //     enc_mnemonic,
        //     identifier,
        //     ipfs_id,
        //     wallet_ids: vec![],
        //     im_token_meta: metadata,
        // };

        Ok(Identity {
            enc_auth_key,
            enc_key: hex::encode(enc_key_bytes),
            identifier,
            ipfs_id,
        })
    }

    pub fn calculate_ipfs_id(pub_key: &PublicKey) -> String {
        let multihash = Code::Sha2_256.digest(&pub_key.serialize_uncompressed());
        base58::encode_slice(&multihash.to_bytes())
    }

    // pub fn to_json(&self) -> Result<String> {
    //     Ok(serde_json::to_string(&self)?)
    // }

    // pub fn cache(&self) {
    //     let mut identity_keystore_obj = IDENTITY_KEYSTORE.write();
    //     *identity_keystore_obj = self.to_owned();
    // }

    // pub fn flush(&self) -> Result<()> {
    //     let json = self.to_json()?;
    //     let file_dir = WALLET_KEYSTORE_DIR.read();
    //     let ks_path = format!("{}/{}", file_dir, IDENTITY_KEYSTORE_FILE_NAME);
    //     let path = Path::new(&ks_path);
    //     let mut file = fs::File::create(path)?;
    //     let _ = file.write_all(&json.as_bytes());
    //     Ok(())
    // }

    // pub fn export_identity(&self, password: &str) -> Result<String> {
    //     let decrypt_data = self
    //         .crypto
    //         .use_key(&Key::Password(password.to_string()))?
    //         .plaintext()?;
    //     Ok(String::from_utf8(decrypt_data)?)
    // }

    // pub fn delete_identity(&self, password: &str) -> Result<()> {
    //     if !self.crypto.verify_password(password) {
    //         return Err(Error::WalletInvalidPassword.into());
    //     }

    //     let clean_wallet_keystore_result = IMTKeystore::clean_keystore_dir();
    //     if clean_wallet_keystore_result.is_ok() {
    //         IMTKeystore::clear_keystore_map();
    //         let mut identity_keystore = IDENTITY_KEYSTORE.write();
    //         *identity_keystore = IdentityKeystore::default();
    //     }

    //     Ok(())
    // }

    pub fn encrypt_ipfs(&self, plaintext: &str) -> Result<String> {
        let iv: [u8; 16] = random_u8_16();
        self.encrypt_ipfs_wth_timestamp_iv(plaintext, unix_timestamp(), &iv)
    }
    fn encrypt_ipfs_wth_timestamp_iv(
        &self,
        plaintext: &str,
        timestamp: u64,
        iv: &[u8; 16],
    ) -> Result<String> {
        let mut header = Vec::new();

        header.write_u8(0x03)?;
        header.write_all(&timestamp.to_le_bytes()[..4]);
        header.write_all(iv)?;

        let enc_key = Vec::from_hex(&self.enc_key)?;

        let ciphertext = encrypt_pkcs7(plaintext.as_bytes(), &enc_key[0..16], iv)?;
        let hash = keccak256(&[header.clone(), merkle_hash(&ciphertext).to_vec()].concat());
        let mut signature = Secp256k1PrivateKey::from_slice(&enc_key)?.sign_recoverable(&hash)?;
        //ETH-compatible ec_recover, in chain_id = 1 case, v = 27 + rec_id
        signature[64] += 27;

        let var_len = VarInt(ciphertext.len() as u64);

        let mut payload = vec![];
        payload.write_all(&header)?;
        var_len.consensus_encode(&mut payload)?;
        payload.write_all(&ciphertext)?;
        payload.write_all(&signature)?;

        Ok(payload.to_hex())
    }

    pub fn decrypt_ipfs(&self, ciphertext: &str) -> Result<String> {
        let ciphertext = Vec::<u8>::from_hex(ciphertext)?;
        if ciphertext.len() <= 21 {
            return Err(Error::InvalidEncryptionData.into());
        }

        let mut rdr = Cursor::new(&ciphertext);
        let mut header = vec![];

        let version = rdr.read_u8()?;
        if version != 0x03 {
            return Err(Error::UnsupportEncryptionDataVersion.into());
        }
        header.write_u8(version)?;
        header.write_u32::<LittleEndian>(rdr.read_u32::<LittleEndian>()?)?;

        let mut iv = [0u8; 16];
        rdr.read(&mut iv)?;
        header.write(&iv)?;

        let var_len = VarInt::consensus_decode(&mut rdr)?;
        if var_len.0 as usize != ciphertext.len() - 21 - 65 - var_len.len() {
            return Err(Error::InvalidEncryptionData.into());
        }

        let mut enc_data = vec![0u8; var_len.0 as usize];
        rdr.read(&mut enc_data)?;

        let mut signature = [0u8; 64];
        rdr.read(&mut signature)?;

        let recover_id = RecoveryId::from_i32(rdr.read_u8()? as i32 - 27)?;

        let hash = keccak256(
            [header, merkle_hash(&enc_data).to_vec()]
                .concat()
                .as_slice(),
        );

        let message = Message::from_slice(&hash)?;
        let sig = RecoverableSignature::from_compact(&signature, recover_id)?;
        let pub_key = Secp256k1::new().recover_ecdsa(&message, &sig)?;
        let ipfs_id = Self::calculate_ipfs_id(&pub_key);

        if self.ipfs_id != ipfs_id {
            return Err(Error::InvalidEncryptionDataSignature.into());
        }

        let enc_key = Vec::from_hex(&self.enc_key)?;
        let plaintext = decrypt_pkcs7(&enc_data, &enc_key[..16], &iv)?;

        Ok(String::from_utf8(plaintext)?)
    }

    pub fn sign_authentication_message(
        &self,
        access_time: u64,
        device_token: &str,
        unlocker: &Unlocker,
    ) -> Result<String> {
        // let unlocker = self.crypto.use_key(&Key::Password(password.to_string()))?;
        let enc_auth_key = unlocker.decrypt_enc_pair(&self.enc_auth_key)?;
        let mut signature = Secp256k1PrivateKey::from_slice(&enc_auth_key)?.sign_recoverable(
            &keccak256(format!("{}.{}.{}", access_time, self.identifier, device_token).as_bytes()),
        )?;
        signature[64] += 27;
        Ok(format!("0x{}", signature.to_hex()))
    }

    // pub fn get_wallets(&self) -> Result<Vec<IMTKeystore>> {
    //     let ids = &self.wallet_ids;
    //     let dir = WALLET_KEYSTORE_DIR.read();

    //     let mut wallets = WALLETS.write();
    //     let mut ret_wallets = Vec::new();
    //     let mut keystore_context = String::new();
    //     for id in ids {
    //         if wallets.get(id.as_str()).is_some() {
    //             ret_wallets.push(wallets.get(id.as_str()).unwrap().clone());
    //             continue;
    //         }

    //         let path_str = format!("{}/{}.json", dir.as_str(), id);
    //         let path = Path::new(path_str.as_str());
    //         if !path.exists() {
    //             return Err(Error::KeystoreFileNotExist.into());
    //         }
    //         let mut file = File::open(&path)?;
    //         file.read_to_string(&mut keystore_context)?;
    //         let imt_keystore: IMTKeystore = serde_json::from_str(keystore_context.as_str())?;
    //         ret_wallets.push(imt_keystore.to_owned());
    //         wallets.insert(id.to_string(), imt_keystore);
    //     }
    //     Ok(ret_wallets)
    // }
}

// pub struct Identity();

// impl Identity {
//     pub fn get_current_identity() -> Result<IdentityKeystore> {
//         let mut identity_keystore_obj = IDENTITY_KEYSTORE.write();
//         if !identity_keystore_obj.id.is_empty() {
//             return Ok(identity_keystore_obj.to_owned());
//         }
//         let dir = WALLET_KEYSTORE_DIR.read();
//         let path_str = format!("{}/{}", dir.as_str(), IDENTITY_KEYSTORE_FILE_NAME);
//         let path = Path::new(path_str.as_str());
//         if !path.exists() {
//             return Err(Error::KeystoreFileNotExist.into());
//         }
//         let mut file = File::open(&path)?;
//         let mut keystore_context = String::new();
//         file.read_to_string(&mut keystore_context)?;
//         let identity_keystore: IdentityKeystore = serde_json::from_str(keystore_context.as_str())?;
//         *identity_keystore_obj = identity_keystore.to_owned();

//         Ok(identity_keystore)
//     }

//     pub fn create_identity(param: CreateIdentityParam) -> Result<IdentityKeystore> {
//         let name = param.name.as_str();
//         let password = param.password.as_str();
//         let password_hint = param.password_hint;
//         let network = param.network.as_str();
//         let seg_wit = param.seg_wit.as_deref();
//         let mnemonic_phrase = tcx_primitive::generate_mnemonic();

//         let metadata = Metadata::new(
//             name,
//             password_hint.clone(),
//             FROM_NEW_IDENTITY,
//             network,
//             None,
//             seg_wit,
//         )?;
//         let mut identity_keystore =
//             IdentityKeystore::new(metadata.clone(), password, mnemonic_phrase.as_str())?;

//         let eth_keystore = Self::derive_ethereum_wallet(
//             password_hint,
//             FROM_NEW_IDENTITY,
//             mnemonic_phrase.as_str(),
//             password,
//         )?;

//         identity_keystore.wallet_ids.push(eth_keystore.id);
//         identity_keystore.flush()?;
//         identity_keystore.cache();

//         Ok(identity_keystore)
//     }

//     pub fn recover_identity(param: RecoverIdentityParam) -> Result<IdentityKeystore> {
//         let name = param.name.as_str();
//         let password = param.password.as_str();
//         let password_hint = param.password_hint;
//         let network = param.network.as_str();
//         let seg_wit = param.seg_wit.as_deref();
//         let mnemonic_phrase = param.mnemonic.as_str();
//         let metadata = Metadata::new(
//             name,
//             password_hint.clone(),
//             FROM_RECOVERED_IDENTITY,
//             network,
//             None,
//             seg_wit,
//         )?;
//         let mut identity_keystore = IdentityKeystore::new(metadata, password, mnemonic_phrase)?;
//         let eth_keystore = Self::derive_ethereum_wallet(
//             password_hint,
//             FROM_RECOVERED_IDENTITY,
//             mnemonic_phrase,
//             password,
//         )?;

//         identity_keystore.wallet_ids.push(eth_keystore.id);
//         identity_keystore.flush()?;
//         identity_keystore.cache();

//         Ok(identity_keystore)
//     }

//     fn derive_ethereum_wallet(
//         password_hint: Option<String>,
//         source: &str,
//         mnemonic_phrase: &str,
//         password: &str,
//     ) -> Result<IMTKeystore> {
//         let mut metadata = Metadata::default();
//         metadata.chain_type = Some(CHAIN_TYPE_ETHEREUM.to_string());
//         metadata.password_hint = password_hint;
//         metadata.source = source.to_string();
//         metadata.name = "ETH".to_string();
//         let imt_keystore = IMTKeystore::create_v3_mnemonic_keystore(
//             &mut metadata,
//             password,
//             mnemonic_phrase,
//             ETHEREUM_PATH,
//         )?;
//         imt_keystore.create_wallet()?;
//         Ok(imt_keystore)
//     }
// }

// #[cfg(test)]
// mod test {
//     use crate::identity::Identity;
//     use crate::model::FROM_NEW_IDENTITY;
//     use crate::wallet_api::{CreateIdentityParam, RecoverIdentityParam};
//     use tcx_constants::sample_key::{MNEMONIC, NAME, PASSWORD, PASSWORD_HINT};
//     use tcx_constants::{sample_key, TEST_MNEMONIC};
//     #[test]
//     fn test_ipfs() {
//         let param = RecoverIdentityParam {
//             name: NAME.to_string(),
//             mnemonic: MNEMONIC.to_string(),
//             password: PASSWORD.to_string(),
//             password_hint: Some(PASSWORD_HINT.to_string()),
//             network: "TESTNET".to_string(),
//             seg_wit: None,
//         };
//         let keystore = Identity::recover_identity(param).unwrap();

//         // header: data, iv, encrypted data
//         let test_cases = [
//             ("imToken", "11111111111111111111111111111111", "0340b2495a1111111111111111111111111111111110b6602c68084bdd08dae796657aa6854ad13312fedc88f5b6f16c56b3e755dde125a1c4775db536ac0442ac942f9634c777f3ae5ca39f6abcae4bd6c87e54ab29ae0062b04d917b32e8d7c88eeb6261301b"),
//             ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "11111111111111111111111111111111", "0340b2495a11111111111111111111111111111111708b7e9486a339f6c482ec9d3786dd9f99222fa64753bc2e7d246b0fed9c2153b8a5dcc59ea3e320aa153ceefdd909e8484d215121a9b8416d395de38313ef65b9e27d2ba0cc17bf29c5b26fa5aa5be1a2500b017f06cdd001e8cd908c5a48f10962880a61b4704754fd6bbe3b5a1a8332376651c28205a02574ed95a70363e0d1031d133c8d2376808b74ffd78b831ec659b44e9f3d3734d26abd44dda88fac86d1a5f0128f77d0558fb1ef6d2cc8f9541c"),
//             ("a", "11111111111111111111111111111111", "0340b2495a111111111111111111111111111111111084e741e2b83ec644e844985088fd58d8449cb690cd7389d74e3be1ccdca755b0235c90431b7635a441944d880bd52c860b109b7a05a960192719eb3f294ec1b72f5dfd1b8f4c6e992b9c3add7c7c1b871b"),
//             ("A", "11111111111111111111111111111111", "0340b2495a1111111111111111111111111111111110de32f176b67269ddfe24b2162eae14968d2eafcb53ec5741a07a1d65dc10189e0f6b4c199e98b02fcb9ec744b134cecc4ae8bfbf79e7703781c259eab9ee2fa31f887b24d04b37b7c5aa49a3ff2a8d5e1b"),
//             ("a", "11111111111111111111111111111111", "0340b2495a111111111111111111111111111111111084e741e2b83ec644e844985088fd58d8449cb690cd7389d74e3be1ccdca755b0235c90431b7635a441944d880bd52c860b109b7a05a960192719eb3f294ec1b72f5dfd1b8f4c6e992b9c3add7c7c1b871b"),
//             ("a", "22222222222222222222222222222222", "0340b2495a22222222222222222222222222222222102906146aa78fadd4abac01d9aa34dbd66463220fa0a98b9212594e7624a34bb20ba50df75cb04362f8dcfe7a8c44b2b5740a2d66de015d867e609463482686959ebba6047600562fa82e94ee905f1d291c"),
//         ];

//         let unix_timestamp = 1514779200u64;
//         for t in test_cases {
//             let iv: [u8; 16] = hex::decode(t.1).unwrap().try_into().unwrap();
//             assert_eq!(
//                 keystore
//                     .encrypt_ipfs_wth_timestamp_iv(t.0, unix_timestamp, &iv)
//                     .unwrap(),
//                 t.2
//             );
//             assert_eq!(keystore.decrypt_ipfs(t.2).unwrap(), t.0);
//         }
//     }

//     #[test]
//     fn test_authentication() {
//         let test_cases =  [
//             ("MAINNET", "0x120cc977f9023c90635144bd0f4c8b85ff8aa23c003edcced9449f0465d05e954bccf9c114484e472c1837b0394f1933ad78ec8050673099e8bf5e9329737fe01c"),
//             ("TESTNET", "0x663ace6d60225f6d1a71d25735c66646f71977a9f25f709fca162db3c664a1e161881a51a8034c240dd8f0093285fd6245f65246708546e8eadd592f995daeb11c"),
//         ];

//         for item in test_cases {
//             let param = RecoverIdentityParam {
//                 name: NAME.to_string(),
//                 mnemonic: MNEMONIC.to_string(),
//                 password: PASSWORD.to_string(),
//                 password_hint: Some(PASSWORD_HINT.to_string()),
//                 network: item.0.to_string(),
//                 seg_wit: None,
//             };
//             let keystore = Identity::recover_identity(param).unwrap();

//             let actual = keystore
//                 .sign_authentication_message(1514736000, "12345ABCDE", PASSWORD)
//                 .unwrap();
//             assert_eq!(actual, item.1);
//         }
//     }

//     #[test]
//     fn test_create_identity() {
//         let param = CreateIdentityParam {
//             name: sample_key::NAME.to_string(),
//             password: PASSWORD.to_string(),
//             password_hint: Some(PASSWORD_HINT.to_string()),
//             network: "TESTNET".to_string(),
//             seg_wit: None,
//         };
//         let identity_keystore = Identity::create_identity(param).unwrap();
//         let imt_keystore_id = identity_keystore.wallet_ids.get(0).unwrap();
//         let ret = Identity::get_current_identity();
//         assert_eq!(ret.is_ok(), true);
//         assert_eq!(ret.unwrap().wallet_ids.get(0).unwrap(), imt_keystore_id);
//     }

//     #[test]
//     fn test_recover_identity() {
//         let param = RecoverIdentityParam {
//             name: NAME.to_string(),
//             mnemonic: MNEMONIC.to_string(),
//             password: PASSWORD.to_string(),
//             password_hint: Some(PASSWORD_HINT.to_string()),
//             network: "TESTNET".to_string(),
//             seg_wit: None,
//         };
//         let recover_result = Identity::recover_identity(param);
//         assert_eq!(recover_result.is_ok(), true);
//         let identity_keystore = Identity::get_current_identity().unwrap();
//         let wallets = identity_keystore.get_wallets().unwrap();
//         assert_eq!(wallets.len(), 1);
//         assert_eq!(
//             "6031564e7b2f5cc33737807b2e58daff870b590b",
//             wallets.get(0).unwrap().address
//         );
//     }
// }
