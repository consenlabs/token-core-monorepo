use crate::keystore::IdentityNetwork;
use crate::Error;
use crate::Result;
use bip39::{Language, Mnemonic, Seed};
use bitcoin::blockdata::constants::PUBKEY_ADDRESS_PREFIX_MAIN;
use bitcoin::blockdata::constants::PUBKEY_ADDRESS_PREFIX_TEST;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::network::constants::Network;
use bitcoin::util::base58;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::key::PrivateKey;
use bitcoin::VarInt;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac_sha256::HMAC;
use multihash::{Code, MultihashDigest};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use tcx_common::{keccak256, merkle_hash, random_u8_16, unix_timestamp, FromHex, ToHex};
use tcx_crypto::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use tcx_crypto::{crypto::Unlocker, EncPair};
use tcx_primitive::{PrivateKey as TraitPrivateKey, Secp256k1PrivateKey};

// lazy_static! {
//     pub static ref IDENTITY_KEYSTORE: RwLock<IdentityKeystore> =
//         RwLock::new(IdentityKeystore::default());
// }

pub const IDENTITY_KEYSTORE_FILE_NAME: &'static str = "identity.json";
pub const VERSION: u32 = 1000;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub enc_auth_key: EncPair,
    pub enc_key: String,
    pub identifier: String,
    pub ipfs_id: String,
}

impl Identity {
    pub fn new(seed: &Seed, unlocker: &Unlocker, network: &IdentityNetwork) -> Result<Self> {
        let network_type = if network == &IdentityNetwork::Mainnet {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let master_key = ExtendedPrivKey::new_master(network_type, seed.as_ref())?;

        let network_salt = if network == &IdentityNetwork::Mainnet {
            "Mainnet"
        } else {
            "Testnet"
        };
        let salt = format!("Automatic Backup Key {}", network_salt);

        let backup_key = HMAC::mac(salt.as_bytes(), master_key.private_key.secret_bytes());

        let authentication_key = HMAC::mac("Authentication Key".as_bytes(), backup_key);

        let auth_private_key = PrivateKey::from_slice(authentication_key.as_ref(), network_type)?;
        let secp = Secp256k1::new();
        let auth_pubkey_hash = auth_private_key.public_key(&secp).pubkey_hash();

        let network_header = if network == &IdentityNetwork::Mainnet {
            PUBKEY_ADDRESS_PREFIX_MAIN
        } else {
            PUBKEY_ADDRESS_PREFIX_TEST
        };

        let version = 2;
        let magic_hex = "0fdc0c"; // a magic header to generate a im prefix after base58
        let full_identifier = format!(
            "{}{:02x}{:02x}{:02x}",
            magic_hex, network_header, version, auth_pubkey_hash
        );
        let identifier = base58::check_encode_slice(Vec::from_hex(full_identifier)?.as_slice());

        //gen enckey
        let enc_key_bytes = HMAC::mac("Encryption Key".as_bytes(), backup_key);

        let enc_private_key = PrivateKey::new_uncompressed(
            secp256k1::SecretKey::from_slice(enc_key_bytes.as_ref())?,
            network_type,
        );
        let multihash =
            Code::Sha2_256.digest(enc_private_key.public_key(&secp).to_bytes().as_slice());
        let ipfs_id = base58::encode_slice(&multihash.to_bytes());
        let enc_auth_key = unlocker.encrypt_with_random_iv(authentication_key.as_slice())?;

        Ok(Identity {
            enc_auth_key,
            enc_key: enc_key_bytes.to_hex(),
            identifier,
            ipfs_id,
        })
    }

    pub fn from_mnemonic(
        mnemonic_phrase: &str,
        unlocker: &Unlocker,
        network: &IdentityNetwork,
    ) -> Result<Self> {
        let validate_result = Mnemonic::validate(mnemonic_phrase, Language::English);
        if validate_result.is_err() {
            return Err(Error::InvalidMnemonic.into());
        }
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        return Self::new(&seed, unlocker, network);
    }

    pub fn from_private_key(
        private_key: &str,
        unlocker: &Unlocker,
        network: &IdentityNetwork,
    ) -> Result<Self> {
        let entropy = Vec::from_hex_auto(private_key)?;
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        return Self::new(&seed, unlocker, network);
    }

    pub fn calculate_ipfs_id(pub_key: &PublicKey) -> String {
        let multihash = Code::Sha2_256.digest(&pub_key.serialize_uncompressed());
        base58::encode_slice(&multihash.to_bytes())
    }

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
        header.write_all(&timestamp.to_le_bytes()[..4])?;
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
        let enc_auth_key = unlocker.decrypt_enc_pair(&self.enc_auth_key)?;
        let mut signature = Secp256k1PrivateKey::from_slice(&enc_auth_key)?.sign_recoverable(
            &keccak256(format!("{}.{}.{}", access_time, self.identifier, device_token).as_bytes()),
        )?;
        signature[64] += 27;
        Ok(format!("0x{}", signature.to_hex()))
    }
}

#[cfg(test)]
mod test {
    use tcx_common::FromHex;
    use tcx_constants::sample_key::{MNEMONIC, PASSWORD, PRIVATE_KEY};
    use tcx_crypto::Key;

    use crate::{keystore::IdentityNetwork, HdKeystore, Metadata, PrivateKeystore};

    #[test]
    fn test_ipfs() {
        let mut meta = Metadata::default();
        meta.network = IdentityNetwork::Testnet;
        let mut keystore = HdKeystore::from_mnemonic(&MNEMONIC, &PASSWORD, meta).unwrap();
        keystore.unlock_by_password(PASSWORD).unwrap();
        let identity = keystore.identity();

        let test_cases = [
            ("imToken", "11111111111111111111111111111111", "0340b2495a1111111111111111111111111111111110b6602c68084bdd08dae796657aa6854ad13312fedc88f5b6f16c56b3e755dde125a1c4775db536ac0442ac942f9634c777f3ae5ca39f6abcae4bd6c87e54ab29ae0062b04d917b32e8d7c88eeb6261301b"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "11111111111111111111111111111111", "0340b2495a11111111111111111111111111111111708b7e9486a339f6c482ec9d3786dd9f99222fa64753bc2e7d246b0fed9c2153b8a5dcc59ea3e320aa153ceefdd909e8484d215121a9b8416d395de38313ef65b9e27d2ba0cc17bf29c5b26fa5aa5be1a2500b017f06cdd001e8cd908c5a48f10962880a61b4704754fd6bbe3b5a1a8332376651c28205a02574ed95a70363e0d1031d133c8d2376808b74ffd78b831ec659b44e9f3d3734d26abd44dda88fac86d1a5f0128f77d0558fb1ef6d2cc8f9541c"),
            ("a", "11111111111111111111111111111111", "0340b2495a111111111111111111111111111111111084e741e2b83ec644e844985088fd58d8449cb690cd7389d74e3be1ccdca755b0235c90431b7635a441944d880bd52c860b109b7a05a960192719eb3f294ec1b72f5dfd1b8f4c6e992b9c3add7c7c1b871b"),
            ("A", "11111111111111111111111111111111", "0340b2495a1111111111111111111111111111111110de32f176b67269ddfe24b2162eae14968d2eafcb53ec5741a07a1d65dc10189e0f6b4c199e98b02fcb9ec744b134cecc4ae8bfbf79e7703781c259eab9ee2fa31f887b24d04b37b7c5aa49a3ff2a8d5e1b"),
            ("a", "11111111111111111111111111111111", "0340b2495a111111111111111111111111111111111084e741e2b83ec644e844985088fd58d8449cb690cd7389d74e3be1ccdca755b0235c90431b7635a441944d880bd52c860b109b7a05a960192719eb3f294ec1b72f5dfd1b8f4c6e992b9c3add7c7c1b871b"),
            ("a", "22222222222222222222222222222222", "0340b2495a22222222222222222222222222222222102906146aa78fadd4abac01d9aa34dbd66463220fa0a98b9212594e7624a34bb20ba50df75cb04362f8dcfe7a8c44b2b5740a2d66de015d867e609463482686959ebba6047600562fa82e94ee905f1d291c"),
        ];

        let unix_timestamp = 1514779200u64;
        for t in test_cases {
            let iv: [u8; 16] = Vec::from_hex(t.1).unwrap().try_into().unwrap();
            assert_eq!(
                identity
                    .encrypt_ipfs_wth_timestamp_iv(t.0, unix_timestamp, &iv)
                    .unwrap(),
                t.2
            );
            assert_eq!(identity.decrypt_ipfs(t.2).unwrap(), t.0);
        }
    }

    #[test]
    fn test_authentication() {
        let test_cases =  [
            (IdentityNetwork::Mainnet, "0x120cc977f9023c90635144bd0f4c8b85ff8aa23c003edcced9449f0465d05e954bccf9c114484e472c1837b0394f1933ad78ec8050673099e8bf5e9329737fe01c"),
            (IdentityNetwork::Testnet, "0x663ace6d60225f6d1a71d25735c66646f71977a9f25f709fca162db3c664a1e161881a51a8034c240dd8f0093285fd6245f65246708546e8eadd592f995daeb11c"),
        ];

        for item in test_cases {
            let mut meta = Metadata::default();
            meta.network = item.0;
            let keystore = HdKeystore::from_mnemonic(&MNEMONIC, &PASSWORD, meta).unwrap();
            // keystore.unlock_by_password(PASSWORD).unwrap();
            let key = Key::Password(PASSWORD.to_string());
            let unlocker = keystore.store().crypto.use_key(&key).unwrap();
            let identity = keystore.identity();

            let actual = identity.sign_authentication_message(1514736000, "12345ABCDE", &unlocker);
            assert_eq!(actual.unwrap(), item.1);
        }
    }

    #[test]
    fn test_create_identity_from_mnemonic() {
        let meta = Metadata::default();
        let keystore = HdKeystore::from_mnemonic(&MNEMONIC, &PASSWORD, meta).unwrap();
        let identity = keystore.identity();

        assert_eq!(
            "im14x5GXsdME4JsrHYe2wvznqRz4cUhx2pA4HPf",
            identity.identifier
        );
        assert_eq!(
            "QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6",
            identity.ipfs_id
        );
    }

    #[test]
    fn test_create_identity_from_private_key() {
        let meta = Metadata::default();
        let keystore = PrivateKeystore::from_private_key(&PRIVATE_KEY, &PASSWORD, meta);
        let identity = &keystore.store().identity;

        assert_eq!(
            "im14x5Ka4SC7WkwL1PzPtHvB1jdzLyaJ3tru511",
            identity.identifier
        );
        assert_eq!(
            "QmWqwovhrZBMmo32BzY83ZMEBQaP7YRMqXNmMc8mgrpzs6",
            identity.ipfs_id
        );
    }
}