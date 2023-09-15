use super::Result;
use crate::handler::encode_message;
use prost::Message;
use tcx_identity::identity::Identity;
use tcx_identity::wallet_api::{
    CreateIdentityParam, CreateIdentityResult, DecryptDataFromIpfsParam, EncryptDataToIpfsParam,
    EncryptDataToIpfsResult, ExportIdentityParam, ExportIdentityResult, GenerateMnemonicResult,
    GetCurrentIdentityResult, ImtKeystore, Metadata as MetadataRes, RecoverIdentityParam,
    RecoverIdentityResult, RemoveIdentityParam, RemoveIdentityResult,
    SignAuthenticationMessageParam, SignAuthenticationMessageResult, Wallet,
};

pub(crate) fn create_identity(data: &[u8]) -> Result<Vec<u8>> {
    let param: CreateIdentityParam = CreateIdentityParam::decode(data)?;
    let identity_keystore = Identity::create_identity(param)?;

    let current_identity: GetCurrentIdentityResult =
        GetCurrentIdentityResult::decode(get_current_identity()?.as_slice()).unwrap();
    let wallets = create_wallets(current_identity.wallets);
    let result = CreateIdentityResult {
        identifier: identity_keystore.identifier.clone(),
        ipfs_id: identity_keystore.ipfs_id.clone(),
        wallets,
    };

    encode_message(result)
}

fn create_wallets(wallets: Vec<ImtKeystore>) -> Vec<Wallet> {
    let mut ret_data = vec![];
    for imt_keystore in wallets {
        let metadata = imt_keystore.metadata.unwrap().clone();
        ret_data.push(Wallet {
            id: imt_keystore.id,
            address: imt_keystore.address,
            created_at: metadata.timestamp,
            source: metadata.source,
            chain_type: metadata.chain_type,
        });
    }
    ret_data
}

pub(crate) fn get_current_identity() -> Result<Vec<u8>> {
    let current_identity = Identity::get_current_identity()?;
    let wallets = current_identity.get_wallets()?;
    let im_token_meta = current_identity.im_token_meta;
    let identity_metadata = MetadataRes {
        name: im_token_meta.name,
        password_hint: im_token_meta.password_hint,
        chain_type: im_token_meta.chain_type.unwrap_or("".to_string()),
        timestamp: im_token_meta.timestamp as u64,
        network: im_token_meta.network,
        backup: im_token_meta.backup.unwrap_or(vec![]),
        source: im_token_meta.source,
        mode: im_token_meta.mode,
        wallet_type: im_token_meta.wallet_type,
        seg_wit: im_token_meta.seg_wit,
    };
    let mut ret_wallet = vec![];
    for wallet in wallets {
        let temp_metadata = wallet.im_token_meta.unwrap();
        let wallet_metadata = MetadataRes {
            name: temp_metadata.name,
            password_hint: temp_metadata.password_hint,
            chain_type: temp_metadata.chain_type.unwrap_or("".to_string()),
            timestamp: temp_metadata.timestamp as u64,
            network: temp_metadata.network,
            backup: temp_metadata.backup.unwrap_or(vec![]),
            source: temp_metadata.source,
            mode: temp_metadata.mode,
            wallet_type: temp_metadata.wallet_type,
            seg_wit: temp_metadata.seg_wit,
        };
        let imt_keystore = ImtKeystore {
            id: wallet.id,
            version: wallet.version,
            address: wallet.address,
            mnemonic_path: wallet.mnemonic_path,
            metadata: Some(wallet_metadata),
        };
        ret_wallet.push(imt_keystore);
    }
    let result = GetCurrentIdentityResult {
        identifier: current_identity.identifier,
        ipfs_id: current_identity.ipfs_id,
        wallets: ret_wallet,
        metadata: Some(identity_metadata),
    };
    encode_message(result)
}

pub(crate) fn export_identity(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportIdentityParam = ExportIdentityParam::decode(data)?;
    let identifier = param.identifier;
    let password = param.password;
    let identity = Identity::get_current_identity()?;
    if identity.identifier != identifier {
        return Err(format_err!("invalid_identity"));
    }

    let mnemonic = identity.export_identity(password.as_str())?;
    let result = ExportIdentityResult {
        identifier,
        mnemonic,
    };
    encode_message(result)
}

pub(crate) fn recover_identity(data: &[u8]) -> Result<Vec<u8>> {
    let param: RecoverIdentityParam = RecoverIdentityParam::decode(data)?;
    let mnemonic = param.mnemonic.to_owned();

    let identity_keystore = Identity::recover_identity(param)?;

    let current_identity: GetCurrentIdentityResult =
        GetCurrentIdentityResult::decode(get_current_identity()?.as_slice()).unwrap();
    let wallets = create_wallets(current_identity.wallets);
    let result = RecoverIdentityResult {
        identifier: identity_keystore.identifier.clone(),
        mnemonic,
        ipfs_id: identity_keystore.ipfs_id.clone(),
        wallets,
    };

    encode_message(result)
}

pub(crate) fn remove_identity(data: &[u8]) -> Result<Vec<u8>> {
    let param: RemoveIdentityParam = RemoveIdentityParam::decode(data)?;
    let identity = Identity::get_current_identity()?;
    if identity.identifier != param.identifier {
        return Err(format_err!("invalid_identity"));
    }
    identity.delete_identity(param.password.as_str())?;
    let result = RemoveIdentityResult {
        identifier: param.identifier,
    };
    encode_message(result)
}

pub(crate) fn encrypt_data_to_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let input = EncryptDataToIpfsParam::decode(data).expect("EncryptDataToIpfsParam");
    let identity = Identity::get_current_identity()?;
    let ciphertext = identity.encrypt_ipfs(&input.content)?;

    let output = EncryptDataToIpfsResult {
        identifier: identity.identifier.to_string(),
        encrypted: ciphertext,
    };

    encode_message(output)
}

pub(crate) fn decrypt_data_from_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let input = DecryptDataFromIpfsParam::decode(data).expect("EncryptDataToIpfsParam");
    let identity = Identity::get_current_identity()?;
    let ciphertext = identity.decrypt_ipfs(&input.encrypted)?;

    let output = EncryptDataToIpfsResult {
        identifier: identity.identifier.to_string(),
        encrypted: ciphertext,
    };

    encode_message(output)
}

pub(crate) fn sign_authentication_message(data: &[u8]) -> Result<Vec<u8>> {
    let input =
        SignAuthenticationMessageParam::decode(data).expect("SignAuthenticationMessageParam");
    let identity = Identity::get_current_identity()?;

    let signature = identity.sign_authentication_message(
        input.access_time,
        &input.identifier,
        &input.device_token,
    )?;
    encode_message(SignAuthenticationMessageResult {
        signature,
        access_time: input.access_time,
    })
}
