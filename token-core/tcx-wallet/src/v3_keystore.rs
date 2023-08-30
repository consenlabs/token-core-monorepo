use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::identity::Identity;
use crate::imt_keystore::IMTKeystore;
use crate::model::{Metadata, FROM_KEYSTORE, FROM_WIF, V3};
use crate::wallet_api::V3KeystoreImportInput;
use crate::Result;
use failure::format_err;
use tcx_common::util::get_address_from_pubkey;
use tcx_crypto::crypto::{KdfParams, KdfType};
use tcx_crypto::Crypto;
use tcx_crypto::Key;
use tcx_crypto::Pbkdf2Params;
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};
use uuid::Uuid;

const VERSION: u32 = 3;

impl IMTKeystore {
    pub fn create_v3_privkey_keystore(
        metadata: &mut Metadata,
        password: &str,
        private_key: &[u8],
        id: Option<&str>,
    ) -> Result<IMTKeystore> {
        let secp256k1_private_key = Secp256k1PrivateKey::from_slice(private_key)?;
        let address = get_address_from_pubkey(
            secp256k1_private_key
                .public_key()
                .to_uncompressed()
                .as_slice(),
        )?;

        let crypto: Crypto = Crypto::new(password, private_key);

        let id = if id.is_some() {
            id.unwrap().to_string()
        } else {
            Uuid::new_v4().as_hyphenated().to_string()
        };
        metadata.wallet_type = Some(V3.to_string());
        Ok(IMTKeystore {
            id,
            version: VERSION,
            address,
            crypto,
            mnemonic_path: None,
            enc_mnemonic: None,
            im_token_meta: Some(metadata.clone()),
        })
    }

    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<IMTKeystore> {
        let decrypted = self
            .crypto
            .decrypt(Key::Password(old_password.to_string()))?;
        Ok(IMTKeystore::create_v3_privkey_keystore(
            &mut self.im_token_meta.as_mut().unwrap(),
            new_password,
            &decrypted,
            Some(self.id.as_str()),
        )?)
    }

    pub fn validate(&self, password: &str) -> Result<()> {
        if self.address.is_empty() {
            return Err(format_err!("{}", "wallet_not_found"));
        }
        // imported_keystore.crypto.kdfparams.validate()?;

        if !self.crypto.verify_password(password) {
            return Err(format_err!("password error"));
        }

        let private_key = self.crypto.decrypt(Key::Password(password.to_string()))?;

        let private_key = Secp256k1PrivateKey::from_slice(&private_key)?;
        let address =
            get_address_from_pubkey(private_key.public_key().to_uncompressed().as_slice())?;
        if address.is_empty() || !address.eq_ignore_ascii_case(&self.address) {
            return Err(format_err!("password error"));
        }
        Ok(())
    }
}

pub fn import_wallet_from_keystore(input: V3KeystoreImportInput) -> Result<IMTKeystore> {
    let json = if input.keystore.contains("scrypt") {
        input.keystore.replace("kdfparams", "scryptparams")
    } else {
        input.keystore
    };
    let keystore: IMTKeystore = serde_json::from_str(&json)?;
    keystore.validate(&input.password)?;
    let private_key = keystore
        .crypto
        .decrypt(Key::Password(input.password.clone()))?;
    //私钥校验

    let source = if input.source.is_empty() {
        FROM_KEYSTORE.to_string()
    } else {
        input.source
    };

    let mut metadata = Metadata::new(
        &input.name,
        None,
        &source,
        "",
        Some(&input.chain_type),
        None,
    )?;
    let v3_keystore = IMTKeystore::create_v3_privkey_keystore(
        &mut metadata,
        &input.password,
        &private_key,
        Some(&keystore.id),
    )?;
    v3_keystore.create_wallet()?;

    let mut identity = Identity::get_current_identity()?;
    identity.wallet_ids.push(v3_keystore.id.clone());
    identity.flush()?;
    identity.cache();
    Ok(v3_keystore)
}

#[cfg(test)]
mod test {
    use crate::model::{Metadata, NETWORK_MAINNET};

    #[test]
    fn test_create_v3_privkey_keystore() {
        // let metadata = Metadata{
        //     name: "V3Keystore Test".to_string(),
        //     password_hint: None,
        //     chain_type: "ETHEREUM".to_string(),
        //     timestamp: 11,
        //     network: NETWORK_MAINNET.to_string(),
        //     backup: todo!(),
        //     source: todo!(),
        //     mode: todo!(),
        //     wallet_type: todo!(),
        //     seg_wit: todo!(),
        // };
    }

    #[test]
    fn test_change_password() {
        println!("test change password");
        let a = "hello world".as_bytes().to_vec();
        let b = String::from_utf8(a).unwrap();
        println!("{}", b);
    }
}
