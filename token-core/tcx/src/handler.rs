use bytes::BytesMut;
use prost::Message;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use tcx_keystore::keystore::IdentityNetwork;

use tcx_common::{FromHex, ToHex};
use tcx_primitive::{private_key_without_version, TypedPrivateKey};

use tcx_btc_kin::WIFDisplay;
use tcx_keystore::{
    key_hash_from_mnemonic, key_hash_from_private_key, Keystore, KeystoreGuard,
    SignatureParameters, Signer,
};
use tcx_keystore::{Account, HdKeystore, Metadata, PrivateKeystore, Source};

use tcx_crypto::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
use tcx_filecoin::KeyInfo;

use crate::api::derive_accounts_param::Derivation;
use crate::api::sign_param::Key;
use crate::api::{
    AccountResponse, CalcExternalAddressParam, CalcExternalAddressResult, CreateKeystoreParam,
    DecryptDataFromIpfsParam, DecryptDataFromIpfsResult, DeriveAccountsParam, DeriveAccountsResult,
    DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExistsKeystoreResult,
    ExistsMnemonicParam, ExistsPrivateKeyParam, ExportPrivateKeyParam, ExportResult, GeneralResult,
    GenerateMnemonicResult, GetExtendedPublicKeysParam, GetExtendedPublicKeysResult,
    GetPublicKeysParam, GetPublicKeysResult, ImportMnemonicParam, ImportPrivateKeyParam, KeyType,
    KeystoreCommonExistsParam, KeystoreMigrationParam, KeystoreResult,
    SignAuthenticationMessageParam, SignAuthenticationMessageResult, SignHashesParam,
    SignHashesResult, StoreDeleteParam, StoreDeleteResult, WalletKeyParam,
    ZksyncPrivateKeyFromSeedParam, ZksyncPrivateKeyFromSeedResult,
    ZksyncPrivateKeyToPubkeyHashParam, ZksyncPrivateKeyToPubkeyHashResult, ZksyncSignMusigParam,
    ZksyncSignMusigResult,
};
use crate::api::{InitTokenCoreXParam, SignParam};
use crate::error_handling::Result;
use crate::filemanager::{
    self, cache_keystore, clean_keystore, copy_to_v2_if_need, flush_keystore, KEYSTORE_BASE_DIR,
    WALLET_FILE_DIR, WALLET_V2_DIR,
};
use crate::filemanager::{delete_keystore_file, KEYSTORE_MAP};

use crate::IS_DEBUG;

use tcx_keystore::tcx_ensure;

use tcx_constants::coin_info::coin_info_from_param;
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use tcx_crypto::KDF_ROUNDS;
use tcx_eth::transaction::{EthRecoverAddressInput, EthRecoverAddressOutput};
use tcx_keystore::{MessageSigner, TransactionSigner};
use tcx_migration::keystore_upgrade::KeystoreUpgrade;

use tcx_primitive::{Bip32DeterministicPublicKey, Ss58Codec};
use tcx_substrate::{
    decode_substrate_keystore, encode_substrate_keystore, ExportSubstrateKeystoreResult,
    SubstrateKeystore, SubstrateKeystoreParam,
};

use tcx_migration::migration::LegacyKeystore;
use tcx_tezos::{build_tezos_base58_private_key, pars_tezos_private_key};
use zksync_crypto::{private_key_from_seed, private_key_to_pubkey_hash, sign_musig};

use crate::macros::use_chains;

use_chains!(
    tcx_btc_kin::bitcoin,
    tcx_btc_kin::omni,
    tcx_filecoin::filecoin,
    tcx_eos::eos,
    tcx_ckb::nervos,
    tcx_eth::ethereum,
    tcx_atom::cosmos,
    tcx_substrate::polkadot,
    tcx_tezos::tezos,
    tcx_tron::tron,
);

pub(crate) fn encode_message(msg: impl Message) -> Result<Vec<u8>> {
    if *IS_DEBUG.read() {
        println!("{:#?}", msg);
    }
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;
    Ok(buf.to_vec())
}

fn derive_account<'a, 'b>(keystore: &mut Keystore, derivation: &Derivation) -> Result<Account> {
    let mut coin_info = coin_info_from_param(
        &derivation.chain_type,
        &derivation.network,
        &derivation.seg_wit,
        &derivation.curve,
    )?;
    coin_info.derivation_path = derivation.path.to_owned();

    derive_account_internal(&coin_info, keystore)
}

pub fn init_token_core_x(data: &[u8]) -> Result<()> {
    let InitTokenCoreXParam {
        file_dir,
        xpub_common_key,
        xpub_common_iv,
        is_debug,
    } = InitTokenCoreXParam::decode(data).unwrap();
    // TODO: pass the file_dir as keystore root
    *KEYSTORE_BASE_DIR.write() = file_dir.to_string();
    copy_to_v2_if_need()?;

    *WALLET_FILE_DIR.write() = format!("{}/{}", file_dir, WALLET_V2_DIR);

    // *WALLET_KEYSTORE_DIR.write() = file_dir.to_string();
    *XPUB_COMMON_KEY_128.write() = xpub_common_key.to_string();
    *XPUB_COMMON_IV.write() = xpub_common_iv.to_string();

    if is_debug {
        *IS_DEBUG.write() = is_debug;
        if is_debug {
            *KDF_ROUNDS.write() = 1024;
        }
    }
    scan_keystores()?;

    Ok(())
}

pub(crate) fn scan_keystores() -> Result<()> {
    clean_keystore();
    let file_dir = WALLET_FILE_DIR.read();
    let p = Path::new(file_dir.as_str());
    let walk_dir = std::fs::read_dir(p).expect("read dir");
    for entry in walk_dir {
        let entry = entry.expect("DirEntry");
        let fp = entry.path();
        if !fp
            .file_name()
            .expect("file_name")
            .to_str()
            .expect("file_name str")
            .ends_with(".json")
        {
            continue;
        }

        let mut f = fs::File::open(fp).expect("open file");
        let mut contents = String::new();

        let _ = f.read_to_string(&mut contents);
        let v: Value = serde_json::from_str(&contents).expect("read json from content");

        let version = v["version"].as_i64().expect("version");
        if version == i64::from(HdKeystore::VERSION)
            || version == i64::from(PrivateKeystore::VERSION)
        {
            let keystore = Keystore::from_json(&contents)?;
            cache_keystore(keystore);
        }
    }
    Ok(())
}

pub(crate) fn create_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: CreateKeystoreParam =
        CreateKeystoreParam::decode(data).expect("import wallet from mnemonic");

    let mut meta = Metadata::default();
    meta.name = param.name.to_owned();
    meta.password_hint = param.password_hint.to_owned();
    // TODO: change source to NEW_MNEMONIC
    meta.source = Source::Mnemonic;
    meta.network = IdentityNetwork::from_str(&param.network)?;

    let ks = HdKeystore::new(&param.password, meta);

    let keystore = Keystore::Hd(ks);
    flush_keystore(&keystore)?;

    let identity = keystore.identity();

    let meta = keystore.meta();
    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        // TODO: change source to NEW_MNEMONIC
        source: Source::Mnemonic.to_string(),
        created_at: meta.timestamp.clone(),
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
    };

    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub(crate) fn import_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ImportMnemonicParam =
        ImportMnemonicParam::decode(data).expect("import wallet from mnemonic");

    let mut founded_id: Option<String> = None;
    {
        let key_hash = key_hash_from_mnemonic(&param.mnemonic)?;
        let map = KEYSTORE_MAP.read();
        if let Some(founded) = map
            .values()
            .find(|keystore| keystore.key_hash() == key_hash)
        {
            founded_id = Some(founded.id());
        }
    }

    if founded_id.is_some() && !param.overwrite {
        return Err(format_err!("{}", "address_already_exist"));
    }

    let mut meta = Metadata::default();
    meta.name = param.name.to_owned();
    meta.password_hint = param.password_hint.to_owned();
    meta.source = Source::Mnemonic;

    let ks = HdKeystore::from_mnemonic(&param.mnemonic, &param.password, meta)?;

    let mut keystore = Keystore::Hd(ks);

    if founded_id.is_some() {
        keystore.set_id(&founded_id.unwrap());
    }

    flush_keystore(&keystore)?;

    let meta = keystore.meta();

    let identity = keystore.identity();

    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: Source::Mnemonic.to_string(),
        created_at: meta.timestamp.clone(),
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

fn encrypt_xpub(xpub: &str, network: &str) -> Result<String> {
    let xpk = Bip32DeterministicPublicKey::from_hex(xpub)?;
    let ext_pub_key: String;
    if network == "MAINNET" {
        ext_pub_key = xpk.to_ss58check_with_version(&[0x04, 0x88, 0xB2, 0x1E]);
    } else {
        ext_pub_key = xpk.to_ss58check_with_version(&[0x04, 0x35, 0x87, 0xCF]);
    }

    let key = tcx_crypto::XPUB_COMMON_KEY_128.read();
    let iv = tcx_crypto::XPUB_COMMON_IV.read();
    let key_bytes = Vec::from_hex(&*key)?;
    let iv_bytes = Vec::from_hex(&*iv)?;
    let encrypted = encrypt_pkcs7(&ext_pub_key.as_bytes(), &key_bytes, &iv_bytes)?;
    Ok(base64::encode(&encrypted))
}

fn decrypt_xpub(enc_xpub: &str) -> Result<Bip32DeterministicPublicKey> {
    let encrypted = base64::decode(enc_xpub)?;
    let key = tcx_crypto::XPUB_COMMON_KEY_128.read();
    let iv = tcx_crypto::XPUB_COMMON_IV.read();
    let key_bytes = Vec::from_hex(&*key)?;
    let iv_bytes = Vec::from_hex(&*iv)?;
    let data = decrypt_pkcs7(&encrypted, &key_bytes, &iv_bytes)?;

    let xpub_str = String::from_utf8(data)?;
    let (xpub, _) = Bip32DeterministicPublicKey::from_ss58check_with_version(&xpub_str)?;
    Ok(xpub)
}

pub(crate) fn derive_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveAccountsParam = DeriveAccountsParam::decode(data).expect("derive_accounts");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let mut account_responses: Vec<AccountResponse> = vec![];

    for derivation in param.derivations {
        let account = derive_account(guard.keystore_mut(), &derivation)?;
        // TODO: Add utxo model to return xpub
        let enc_xpub = if account.ext_pub_key.is_empty() {
            Ok("".to_string())
        } else {
            encrypt_xpub(&account.ext_pub_key.to_string(), &account.network)
        }?;
        let account_rsp = AccountResponse {
            chain_type: derivation.chain_type.to_owned(),
            address: account.address.to_owned(),
            path: account.derivation_path.to_owned(),
            extended_public_key: enc_xpub,
            public_key: account.public_key,
            curve: account.curve.as_str().to_string(),
        };
        account_responses.push(account_rsp);
    }

    let accounts_rsp = DeriveAccountsResult {
        accounts: account_responses,
    };
    encode_message(accounts_rsp)
}

pub(crate) fn export_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("export_mnemonic");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    tcx_ensure!(
        guard.keystore().derivable(),
        format_err!("{}", "private_keystore_cannot_export_mnemonic")
    );

    let export_result = ExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::Mnemonic as i32,
        value: guard.keystore().export()?,
    };

    encode_message(export_result)
}

fn key_data_from_any_format_pk(pk: &str) -> Result<Vec<u8>> {
    let decoded = Vec::from_hex(pk.to_string());
    if decoded.is_ok() {
        let bytes = decoded.unwrap();
        if bytes.len() <= 64 {
            Ok(bytes)
        } else {
            // import filecoin
            Ok(KeyInfo::from_lotus(&bytes)?.decode_private_key()?)
        }
    } else {
        private_key_without_version(pk)
    }
}

fn key_hash_from_any_format_pk(pk: &str) -> Result<String> {
    let key_data = key_data_from_any_format_pk(pk)?;
    Ok(key_hash_from_private_key(&key_data))
}

fn key_hash_from_tezos_format_pk(pk: &str) -> Result<String> {
    let key_data = pars_tezos_private_key(pk)?;
    Ok(key_hash_from_private_key(&key_data))
}

pub(crate) fn import_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ImportPrivateKeyParam =
        ImportPrivateKeyParam::decode(data).expect("import_private_key");

    let mut founded_id: Option<String> = None;
    {
        let key_hash: String;
        if param.encoding.eq("TEZOS") {
            key_hash = key_hash_from_tezos_format_pk(&param.private_key)?;
        } else {
            key_hash = key_hash_from_any_format_pk(&param.private_key)?;
        }
        //        let key_hash = key_hash_from_any_format_pk(&param.private_key)?;
        let map = KEYSTORE_MAP.read();
        if let Some(founded) = map
            .values()
            .find(|keystore| keystore.key_hash() == key_hash)
        {
            founded_id = Some(founded.id());
        }
    }

    if founded_id.is_some() && !param.overwrite {
        return Err(format_err!("{}", "address_already_exist"));
    }

    let pk_bytes: Vec<u8>;
    if param.encoding.eq("TEZOS") {
        pk_bytes = pars_tezos_private_key(&param.private_key)?;
    } else {
        pk_bytes = key_data_from_any_format_pk(&param.private_key)?;
    }
    let private_key = pk_bytes.to_hex();
    let meta = Metadata {
        name: param.name,
        password_hint: param.password_hint,
        source: Source::Private,
        ..Metadata::default()
    };
    let pk_store = PrivateKeystore::from_private_key(&private_key, &param.password, meta);

    let mut keystore = Keystore::PrivateKey(pk_store);

    if let Some(exist_kid) = founded_id {
        keystore.set_id(&exist_kid)
    }

    flush_keystore(&keystore)?;

    let meta = keystore.meta();
    let identity = keystore.identity();
    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: "PRIVATE".to_owned(),
        created_at: meta.timestamp.clone(),
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub(crate) fn export_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam =
        ExportPrivateKeyParam::decode(data).expect("export_private_key");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let curve = CurveType::from_str(&param.curve);
    let pk_bytes = guard
        .keystore_mut()
        .get_private_key(curve, &param.path)?
        .to_bytes();
    let pk_hex = pk_bytes.to_hex();

    // private_key prefix is only about chain type and network
    // TODO: add export_pk to macro
    let value = if ["TRON", "POLKADOT", "KUSAMA"].contains(&param.chain_type.as_str()) {
        Ok(pk_hex.to_string())
    } else if "FILECOIN".contains(&param.chain_type.as_str()) {
        Ok(KeyInfo::from_private_key(curve, &Vec::from_hex(pk_hex)?)?
            .to_json()?
            .to_hex())
    } else if "TEZOS".contains(&param.chain_type.as_str()) {
        Ok(build_tezos_base58_private_key(pk_hex.as_str())?)
    } else {
        // private_key prefix is only about chain type and network
        let coin_info = coin_info_from_param(&param.chain_type, &param.network, "", "")?;

        let bytes = Vec::from_hex(pk_hex.to_string())?;
        let typed_pk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &bytes)?;
        typed_pk.fmt(&coin_info)
    }?;

    let export_result = ExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::PrivateKey as i32,
        value,
    };

    encode_message(export_result)
}

pub(crate) fn verify_password(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("delete_keystore");
    let map = KEYSTORE_MAP.read();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.password) {
        let rsp = GeneralResult {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(format_err!("{}", "password_incorrect"))
    }
}

pub(crate) fn delete_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("delete_keystore");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.password) {
        delete_keystore_file(&param.id)?;
        map.remove(&param.id);

        let rsp = GeneralResult {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(format_err!("{}", "password_incorrect"))
    }
}

pub(crate) fn exists_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsPrivateKeyParam =
        ExistsPrivateKeyParam::decode(data).expect("ExistsPrivateKeyParam");
    let key_hash = if param.encoding.eq("TEZOS") {
        key_hash_from_tezos_format_pk(&param.private_key)?
    } else {
        key_hash_from_any_format_pk(&param.private_key)?
    };
    exists_key_hash(&key_hash)
}

pub(crate) fn exists_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsMnemonicParam =
        ExistsMnemonicParam::decode(data).expect("ExistsMnemonicParam");

    let mnemonic: &str = &&param
        .mnemonic
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    let key_hash = key_hash_from_mnemonic(mnemonic)?;

    exists_key_hash(&key_hash)
}

fn exists_key_hash(key_hash: &str) -> Result<Vec<u8>> {
    let map = &KEYSTORE_MAP.read();

    let founded: Option<&Keystore> = map
        .values()
        .find(|keystore| keystore.key_hash() == key_hash);
    let result: ExistsKeystoreResult;
    if let Some(ks) = founded {
        result = ExistsKeystoreResult {
            is_exists: true,
            id: ks.id(),
        }
    } else {
        result = ExistsKeystoreResult {
            is_exists: false,
            id: "".to_owned(),
        }
    }
    encode_message(result)
}

pub(crate) fn keystore_common_exists(data: &[u8]) -> Result<Vec<u8>> {
    let param: KeystoreCommonExistsParam =
        KeystoreCommonExistsParam::decode(data).expect("keystore_common_exists params");
    let key_hash: String;
    if param.r#type == KeyType::Mnemonic as i32 {
        let mnemonic: &str = &param
            .value
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        key_hash = key_hash_from_mnemonic(mnemonic)?;
    } else {
        if param.encoding.eq("TEZOS") {
            key_hash = key_hash_from_tezos_format_pk(&param.value)?;
        } else {
            key_hash = key_hash_from_any_format_pk(&param.value)?;
        }
    }
    let map = &mut KEYSTORE_MAP.write();

    let founded: Option<&Keystore> = map
        .values()
        .find(|keystore| keystore.key_hash() == key_hash);
    let result: ExistsKeystoreResult;
    if let Some(ks) = founded {
        result = ExistsKeystoreResult {
            is_exists: true,
            id: ks.id(),
        }
    } else {
        result = ExistsKeystoreResult {
            is_exists: false,
            id: "".to_owned(),
        }
    }
    encode_message(result)
}

pub(crate) fn sign_tx(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("SignTxParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = match param.key.clone().unwrap() {
        Key::Password(password) => KeystoreGuard::unlock_by_password(keystore, &password)?,
        Key::DerivedKey(derived_key) => {
            KeystoreGuard::unlock_by_derived_key(keystore, &derived_key)?
        }
    };

    sign_transaction_internal(&param, guard.keystore_mut())
}

pub(crate) fn sign_hashes(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignHashesParam = SignHashesParam::decode(data).expect("SignHashesParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;
    let signatures = param
        .data_to_sign
        .iter()
        .map(|data_to_sign| -> Result<String> {
            let hash = Vec::from_hex_auto(&data_to_sign.hash)?;
            let sig = guard.keystore_mut().sign_hash(
                &hash,
                &data_to_sign.path,
                &data_to_sign.curve,
                &data_to_sign.sig_alg,
            )?;
            Ok(sig.to_0x_hex())
        })
        .collect::<Vec<Result<String>>>();
    let signatures = signatures.into_iter().collect::<Result<Vec<String>>>()?;
    encode_message(SignHashesResult { signatures })
}

pub(crate) fn get_public_keys(data: &[u8]) -> Result<Vec<u8>> {
    let param: GetPublicKeysParam = GetPublicKeysParam::decode(data).expect("GetPublicKeysParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;
    let public_keys = param
        .derivations
        .iter()
        .map(|derivation| {
            let public_key = guard
                .keystore_mut()
                .get_public_key(CurveType::from_str(&derivation.curve), &derivation.path)
                .expect("PublicKeyProcessed");
            public_key.to_bytes().to_hex()
        })
        .collect();

    encode_message(GetPublicKeysResult { public_keys })
}

pub(crate) fn get_extended_public_keys(data: &[u8]) -> Result<Vec<u8>> {
    let param: GetExtendedPublicKeysParam =
        GetExtendedPublicKeysParam::decode(data).expect("ExtendedPublicKeyParamPoc");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let extended_public_keys = param
        .derivations
        .iter()
        .map(|derivation| {
            let extended_public_key = guard
                .keystore_mut()
                .get_deterministic_public_key(
                    CurveType::from_str(&derivation.curve),
                    &derivation.path,
                )
                .expect("GetExtendedPublicKeysParam");
            extended_public_key.to_string()
        })
        .collect();
    encode_message(GetExtendedPublicKeysResult {
        extended_public_keys,
    })
}

pub(crate) fn sign_message(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("SignTxParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = match param.key.clone().unwrap() {
        Key::Password(password) => KeystoreGuard::unlock_by_password(keystore, &password)?,
        Key::DerivedKey(derived_key) => {
            KeystoreGuard::unlock_by_derived_key(keystore, &derived_key)?
        }
    };

    sign_message_internal(&param, guard.keystore_mut())
}

pub(crate) fn get_derived_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).unwrap();
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let dk = keystore.get_derived_key(&param.password)?;

    let ret = DerivedKeyResult {
        id: param.id.to_owned(),
        derived_key: dk,
    };
    encode_message(ret)
}

pub(crate) fn import_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: SubstrateKeystoreParam = SubstrateKeystoreParam::decode(data)?;
    let ks: SubstrateKeystore = serde_json::from_str(&param.keystore)?;
    let _ = ks.validate()?;
    let pk = decode_substrate_keystore(&ks, &param.password)?;
    let pk_import_param = ImportPrivateKeyParam {
        private_key: pk.to_hex(),
        password: param.password.to_string(),
        name: ks.meta.name,
        password_hint: "".to_string(),
        overwrite: param.overwrite,
        encoding: "".to_string(),
    };
    let param_bytes = encode_message(pk_import_param)?;
    import_private_key(&param_bytes)
}

pub(crate) fn export_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam = ExportPrivateKeyParam::decode(data)?;
    let meta: Metadata;
    {
        let map = KEYSTORE_MAP.read();

        let keystore: &Keystore = match map.get(&param.id) {
            Some(keystore) => Ok(keystore),
            _ => Err(format_err!("{}", "wallet_not_found")),
        }?;

        // !!! Warning !!! HDKeystore only can export raw sr25519 key,
        // but polkadotjs fixtures needs a Ed25519 expanded secret key.
        if keystore.derivable() {
            return Err(format_err!("{}", "hd_wallet_cannot_export_keystore"));
        }
        meta = keystore.meta().clone();
    }

    let ret = export_private_key(data)?;
    let export_result: ExportResult = ExportResult::decode(ret.as_slice())?;
    let pk = export_result.value;
    let pk_bytes = Vec::from_hex(pk)?;
    let coin = coin_info_from_param(&param.chain_type, &param.network, "", "")?;

    let mut substrate_ks = encode_substrate_keystore(&param.password, &pk_bytes, &coin)?;

    substrate_ks.meta.name = meta.name;
    substrate_ks.meta.when_created = meta.timestamp;
    let keystore_str = serde_json::to_string(&substrate_ks)?;
    let ret = ExportSubstrateKeystoreResult {
        keystore: keystore_str,
    };
    encode_message(ret)
}

pub(crate) fn exists_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: SubstrateKeystoreParam = SubstrateKeystoreParam::decode(data)?;
    let ks: SubstrateKeystore = serde_json::from_str(&param.keystore)?;
    let _ = ks.validate()?;
    let pk = decode_substrate_keystore(&ks, &param.password)?;

    let pk_hex = pk.to_hex();
    let exists_param = KeystoreCommonExistsParam {
        r#type: KeyType::PrivateKey as i32,
        value: pk_hex,
        encoding: "".to_string(),
    };
    let exists_param_bytes = encode_message(exists_param)?;
    keystore_common_exists(&exists_param_bytes)
}

pub(crate) fn unlock_then_crash(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).unwrap();
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let _guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;
    panic!("test_unlock_then_crash");
}

pub(crate) fn zksync_private_key_from_seed(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncPrivateKeyFromSeedParam = ZksyncPrivateKeyFromSeedParam::decode(data)?;

    let result = private_key_from_seed(Vec::from_hex(param.seed)?.as_slice())
        .expect("zksync_private_key_from_seed_error");

    let ret = ZksyncPrivateKeyFromSeedResult {
        priv_key: result.to_hex(),
    };
    encode_message(ret)
}

pub(crate) fn zksync_sign_musig(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncSignMusigParam = ZksyncSignMusigParam::decode(data)?;

    let sign_result = sign_musig(
        Vec::from_hex(param.priv_key)?.as_slice(),
        Vec::from_hex(param.bytes)?.as_slice(),
    )
    .expect("zksync_sign_musig_error");
    let ret = ZksyncSignMusigResult {
        signature: sign_result.to_hex(),
    };
    encode_message(ret)
}

pub(crate) fn zksync_private_key_to_pubkey_hash(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncPrivateKeyToPubkeyHashParam = ZksyncPrivateKeyToPubkeyHashParam::decode(data)?;
    let pub_key_hash = private_key_to_pubkey_hash(Vec::from_hex(param.priv_key)?.as_slice())
        .expect("zksync_private_key_to_pubkey_hash_error");
    let ret = ZksyncPrivateKeyToPubkeyHashResult {
        pub_key_hash: pub_key_hash.to_hex(),
    };
    encode_message(ret)
}

pub(crate) fn generate_mnemonic() -> Result<Vec<u8>> {
    let mnemonic = tcx_primitive::generate_mnemonic();
    let result = GenerateMnemonicResult { mnemonic };
    encode_message(result)
}

pub(crate) fn remove_wallet(data: &[u8]) -> Result<Vec<u8>> {
    let param: StoreDeleteParam = StoreDeleteParam::decode(data)?;
    let map = KEYSTORE_MAP.read();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if !keystore.verify_password(&param.password) {
        return Err(failure::format_err!("password_incorrect"));
    }
    filemanager::delete_keystore_file(&param.id)?;

    let result = StoreDeleteResult { is_success: true };
    encode_message(result)
}

pub(crate) fn eth_recover_address(data: &[u8]) -> Result<Vec<u8>> {
    let input: EthRecoverAddressInput =
        EthRecoverAddressInput::decode(data).expect("EthRecoverAddressParam");
    let result: Result<EthRecoverAddressOutput> = input.recover_address();

    encode_message(result?)
}

pub(crate) fn encrypt_data_to_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let param = EncryptDataToIpfsParam::decode(data).expect("EncryptDataToIpfsParam");

    let map = KEYSTORE_MAP.read();
    let Some(identity_ks) = map.values().find(|ks| ks.identity().identifier == param.identifier) else {
        return Err(failure::format_err!("identity not found"));
    };

    let cipher_text = identity_ks.identity().encrypt_ipfs(&param.content)?;

    let output = EncryptDataToIpfsResult {
        identifier: param.identifier.to_string(),
        encrypted: cipher_text,
    };

    encode_message(output)
}

pub(crate) fn decrypt_data_from_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let param = DecryptDataFromIpfsParam::decode(data).expect("DecryptDataFromIpfsParam");

    let map = KEYSTORE_MAP.read();
    let Some(identity_ks) = map.values().find(|ks| ks.identity().identifier == param.identifier) else {
        return Err(failure::format_err!("identity not found"));
    };

    let content = identity_ks.identity().decrypt_ipfs(&param.encrypted)?;

    let output = DecryptDataFromIpfsResult {
        identifier: param.identifier.to_string(),
        content,
    };

    encode_message(output)
}

pub(crate) fn sign_authentication_message(data: &[u8]) -> Result<Vec<u8>> {
    let param =
        SignAuthenticationMessageParam::decode(data).expect("SignAuthenticationMessageParam");

    let map = KEYSTORE_MAP.read();
    let Some(identity_ks) = map.values().find(|ks| ks.identity().identifier == param.identifier) else {
            return Err(failure::format_err!("identity not found"));
        };

    let key = tcx_crypto::Key::Password(param.password);
    let unlocker = identity_ks.use_key(&key)?;

    let signature = identity_ks.identity().sign_authentication_message(
        param.access_time,
        &param.device_token,
        &unlocker,
    )?;

    encode_message(SignAuthenticationMessageResult {
        signature,
        access_time: param.access_time,
    })
}

// TODO: add eth sub addr support
pub(crate) fn calc_external_address(data: &[u8]) -> Result<Vec<u8>> {
    let param: CalcExternalAddressParam =
        CalcExternalAddressParam::decode(data).expect("CalcExternalAddressParam");

    let xpub = decrypt_xpub(&param.enc_extended_public_key)?;

    let (address, external_path) = tcx_btc_kin::calc_btc_change_address(
        &param.seg_wit,
        &param.network,
        param.external_idx,
        &param.path,
        &xpub,
    )?;
    encode_message(CalcExternalAddressResult {
        address,
        r#type: "EXTERNAL".to_string(),
        derived_path: external_path,
    })
}

pub(crate) fn migrate_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param = KeystoreMigrationParam::decode(data).expect("KeystoreMigrationParam");
    let json_str = fs::read_to_string(format!("{}/{}.json", WALLET_FILE_DIR.read(), param.id))?;
    let json = serde_json::from_str::<Value>(&json_str)?;

    let key = if param.derived_key.is_empty() {
        tcx_crypto::Key::Password(param.password)
    } else {
        tcx_crypto::Key::DerivedKey(param.derived_key)
    };

    let keystore;

    if let Some(version) = json["version"].as_i64() {
        match version {
            11000 | 11001 => {
                let keystore_upgrade = KeystoreUpgrade::new(json);
                keystore = keystore_upgrade.upgrade(&key)?;
            }
            _ => {
                let legacy_keystore = LegacyKeystore::from_json_str(&json_str)?;

                let mut tcx_ks: Option<Keystore> = None;
                {
                    let map = KEYSTORE_MAP.read();
                    if param.tcx_id.len() > 0 {
                        tcx_ks = map.get(&param.tcx_id).and_then(|ks| Some(ks.clone()))
                    }
                }

                keystore = legacy_keystore.migrate_identity_wallets(&key, tcx_ks)?;
            }
        }

        flush_keystore(&keystore)?;
        let identity = keystore.identity();

        let ret = encode_message(KeystoreResult {
            id: keystore.id().to_string(),
            name: keystore.meta().name.to_string(),
            source: keystore.meta().source.to_string(),
            created_at: keystore.meta().timestamp,
            identifier: identity.identifier.to_string(),
            ipfs_id: identity.ipfs_id.to_string(),
        });

        cache_keystore(keystore);
        ret
    } else {
        Err(format_err!("invalid version in keystore"))
    }
}
