use crate::constants::CHAIN_TYPE_ETHEREUM;
use crate::model::Metadata;
use crate::Error;
use crate::Result;
use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tcx_crypto::{Crypto, EncPair, Key, Pbkdf2Params};
// use tcx_eth::address::EthAddress;
use tcx_primitive::{Bip32DeterministicPrivateKey, Derive, DeterministicPrivateKey, PrivateKey};
use uuid::Uuid;

pub const VERSION: u32 = 3;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IMTKeystore {
    pub crypto: Crypto<Pbkdf2Params>,
    pub id: String,
    pub version: u32,
    pub address: String,
    pub mnemonic_path: String,
    pub enc_mnemonic: EncPair,
    pub im_token_meta: Metadata,
}

impl IMTKeystore {
    pub fn create_v3_mnemonic_keystore(
        metadata: &mut Metadata,
        password: &str,
        mnemonic_phrase: &str,
        path: &str,
    ) -> Result<IMTKeystore> {
        Mnemonic::validate(mnemonic_phrase, Language::English).unwrap();

        let bip32_deterministic_privateKey =
            Bip32DeterministicPrivateKey::from_mnemonic(mnemonic_phrase)?;
        let bip32_deterministic_privateKey = bip32_deterministic_privateKey.derive(path)?;

        let mut crypto: Crypto<Pbkdf2Params> = Crypto::new_by_10240_round(
            password,
            bip32_deterministic_privateKey
                .private_key()
                .0
                .to_bytes()
                .as_slice(),
        );
        let enc_mnemonic = crypto.derive_enc_pair(password, mnemonic_phrase.as_bytes())?;
        crypto.clear_cache_derived_key();
        metadata.timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();

        let publick_key = bip32_deterministic_privateKey
            .private_key()
            .public_key()
            .to_uncompressed();

        let address = get_address(
            metadata.chain_type.as_str(),
            metadata.is_main_net(),
            publick_key.as_slice(),
        )?;

        Ok(IMTKeystore {
            crypto,
            id: Uuid::new_v4().as_hyphenated().to_string(),
            version: VERSION,
            address,
            mnemonic_path: path.to_string(),
            enc_mnemonic,
            im_token_meta: metadata.clone(),
        })
    }

    pub fn create_hd_mnemonic_keystore(
        metadata: &mut Metadata,
        password: &str,
        mnemonic_phrase: &str,
        path: &str,
        id: Option<&str>,
    ) -> Result<IMTKeystore> {
        //todo
        Ok(IMTKeystore::default())
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn decrypt_main_key(&self, password: &str) -> Result<Vec<u8>> {
        self.crypto.decrypt(Key::Password(password.to_owned()))
    }
}

impl IMTKeystore {
    fn delete(&self, password: &str) -> Result<()> {
        //TODO
        Ok(())
    }
}

fn get_address(chain_type: &str, is_mainnet: bool, public_key: &[u8]) -> Result<String> {
    let address = match chain_type {
        // CHAIN_TYPE_ETHEREUM => EthAddress::get_address_from_pubkey(public_key)?,
        CHAIN_TYPE_ETHEREUM => "EthAddress::get_address_from_pubkey(public_key)?".to_string(),
        _ => return Err(Error::WalletInvalidType.into()),
    };
    Ok(address)
}

#[cfg(test)]
mod test {
    use crate::constants;
    use crate::constants::{CHAIN_TYPE_ETHEREUM, ETHEREUM_PATH};
    use crate::imt_keystore::{get_address, IMTKeystore};
    use crate::model::{Metadata, FROM_NEW_IDENTITY};
    use tcx_constants::sample_key::{MNEMONIC, PASSWORD, PASSWORD_HINT};
    #[test]
    fn test_get_address() {
        let public_key = hex::decode("0480c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fefbc790fc3291d3cb6441ac94c3952035c409f4374d1780f400c1ed92972ce83c").unwrap();
        let address = get_address(constants::CHAIN_TYPE_ETHEREUM, false, public_key.as_slice());
        assert!(address.is_ok());
        assert_eq!(address.unwrap(), "6031564e7b2f5cc33737807b2e58daff870b590b");

        let address = get_address("WRONG_CHAIN_TYPE", false, public_key.as_slice());
        assert!(address.is_err());
    }

    #[test]
    fn test_create_v3_mnemonic_keystore() {
        let mut metadata = Metadata::default();
        metadata.chain_type = CHAIN_TYPE_ETHEREUM.to_string();
        metadata.password_hint = Some(PASSWORD_HINT.to_string());
        metadata.source = FROM_NEW_IDENTITY.to_string();
        metadata.name = "ETH".to_string();
        let imt_keystore = IMTKeystore::create_v3_mnemonic_keystore(
            &mut metadata,
            PASSWORD,
            MNEMONIC,
            ETHEREUM_PATH,
        )
        .unwrap();
        assert_eq!(
            imt_keystore.address,
            "6031564e7b2f5cc33737807b2e58daff870b590b"
        );
        assert_eq!(
            hex::encode(imt_keystore.decrypt_main_key(PASSWORD).unwrap()),
            "cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2"
        );
    }
}
