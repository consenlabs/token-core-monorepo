use bytes::BytesMut;
use prost::Message;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use tcx_atom::address::{AtomAddress, AtomChainFactory};
use tcx_eos::address::EosAddress;
use tcx_eos::EosChainFactory;
use tcx_primitive::{get_account_path, private_key_without_version, FromHex, TypedPrivateKey};

use tcx_bch::BchAddress;
use tcx_btc_kin::{BtcKinAddress, WIFDisplay};
use tcx_chain::{
    key_hash_from_mnemonic, key_hash_from_private_key, ChainFactory, Keystore, KeystoreGuard,
};
use tcx_chain::{Account, HdKeystore, Metadata, PrivateKeystore, Source};
use tcx_ckb::{CkbAddress, CkbTxInput};
use tcx_crypto::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
use tcx_filecoin::{FilecoinAddress, KeyInfo, UnsignedMessage};
use tcx_tron::TronAddress;

use crate::api::keystore_common_derive_param::Derivation;
use crate::api::sign_param::Key;
use crate::api::{
    AccountResponse, AccountsResponse, DerivedKeyResult, ExportPrivateKeyParam, HdStoreCreateParam,
    HdStoreImportParam, KeyType, KeystoreCommonAccountsParam, KeystoreCommonDeriveParam,
    KeystoreCommonExistsParam, KeystoreCommonExistsResult, KeystoreCommonExportResult,
    KeystoreUpdateAccount, PrivateKeyStoreExportParam, PrivateKeyStoreImportParam, PublicKeyParam,
    PublicKeyResult, Response, WalletKeyParam, WalletResult, ZksyncPrivateKeyFromSeedParam,
    ZksyncPrivateKeyFromSeedResult, ZksyncPrivateKeyToPubkeyHashParam,
    ZksyncPrivateKeyToPubkeyHashResult, ZksyncSignMusigParam, ZksyncSignMusigResult,
};
use crate::api::{InitTokenCoreXParam, SignParam};
use crate::error_handling::Result;
use crate::filemanager::{cache_keystore, clean_keystore, flush_keystore, WALLET_FILE_DIR};
use crate::filemanager::{delete_keystore_file, KEYSTORE_MAP};

use crate::IS_DEBUG;
use base58::ToBase58;
use tcx_atom::transaction::AtomTxInput;
use tcx_chain::tcx_ensure;
use tcx_chain::Address;
use tcx_chain::{MessageSigner, TransactionSigner};
use tcx_constants::coin_info::coin_info_from_param;
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::aes::cbc::encrypt_pkcs7;
use tcx_crypto::hash::dsha256;
use tcx_crypto::KDF_ROUNDS;
use tcx_eos::transaction::EosMessageInput;
use tcx_eth::transaction::{
    EthMessageInput, EthMessageOutput, EthRecoverAddressInput, EthRecoverAddressOutput, EthTxInput,
    EthTxOutput,
};
use tcx_eth2::address::Eth2Address;
use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
use tcx_primitive::{Bip32DeterministicPublicKey, Ss58Codec};
use tcx_substrate::{
    decode_substrate_keystore, encode_substrate_keystore, ExportSubstrateKeystoreResult,
    SubstrateAddress, SubstrateKeystore, SubstrateKeystoreParam, SubstrateRawTxIn,
};
use tcx_tezos::address::TezosAddress;
use tcx_tezos::transaction::TezosRawTxIn;
use tcx_tezos::{build_tezos_base58_private_key, pars_tezos_private_key};
use tcx_tron::transaction::{TronMessageInput, TronTxInput};
use tcx_wallet::identity::Identity;
use tcx_wallet::imt_keystore::{IMTKeystore, WALLET_KEYSTORE_DIR};
use tcx_wallet::v3_keystore::import_wallet_from_keystore;
use tcx_wallet::wallet_api::{
    CreateIdentityParam, CreateIdentityResult, ExportIdentityParam, ExportIdentityResult,
    GenerateMnemonicResult, GetCurrentIdentityResult, ImtKeystore, Metadata as MetadataRes,
    RecoverIdentityParam, RecoverIdentityResult, RemoveIdentityParam, RemoveIdentityResult,
    V3KeystoreExportInput, V3KeystoreExportOutput, V3KeystoreImportInput, Wallet,
};
use zksync_crypto::{private_key_from_seed, private_key_to_pubkey_hash, sign_musig};

use crate::macros::use_chains;

use_chains!(
    tcx_btc_kin::bitcoin,
    tcx_btc_kin::omni,
    tcx_filecoin::filecoin
);

fn create_chain_factory(chain: &str) -> Result<Box<dyn ChainFactory>> {
    match chain {
        "EOS" => Ok(Box::new(EosChainFactory {})),
        "COSMOS" => Ok(Box::new(AtomChainFactory {})),
        _ => Err(format_err!("unknow_chain_factory")),
    }
}

const NO_PK_CHAINS: &[&str] = &["COSMOS"];

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

    /*
    match derivation.chain_type.as_str() {
        "BITCOINCASH" => keystore.derive_coin::<BchAddress>(&coin_info),
        "LITECOIN" | "BITCOIN" => keystore.derive_coin::<BtcKinAddress>(&coin_info),
        "TRON" => keystore.derive_coin::<TronAddress>(&coin_info),
        "NERVOS" => keystore.derive_coin::<CkbAddress>(&coin_info),
        "POLKADOT" | "KUSAMA" => keystore.derive_coin::<SubstrateAddress>(&coin_info),
        "TEZOS" => keystore.derive_coin::<TezosAddress>(&coin_info),
        "FILECOIN" => keystore.derive_coin::<FilecoinAddress>(&coin_info),
        "ETHEREUM2" => keystore.derive_coin::<Eth2Address>(&coin_info),
        "COSMOS" => keystore.derive_coin::<AtomAddress>(&coin_info),
        "EOS" => keystore.derive_coin::<EosAddress>(&coin_info),
        _ => Err(format_err!("unsupported_chain")),
    }
     */
}

pub fn init_token_core_x(data: &[u8]) -> Result<()> {
    let InitTokenCoreXParam {
        file_dir,
        xpub_common_key,
        xpub_common_iv,
        is_debug,
    } = InitTokenCoreXParam::decode(data).unwrap();
    *WALLET_FILE_DIR.write() = file_dir.to_string();
    *WALLET_KEYSTORE_DIR.write() = file_dir.to_string();
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

pub(crate) fn hd_store_create(data: &[u8]) -> Result<Vec<u8>> {
    let param: HdStoreCreateParam =
        HdStoreCreateParam::decode(data).expect("import wallet from mnemonic");

    let mut meta = Metadata::default();
    meta.name = param.name.to_owned();
    meta.password_hint = param.password_hint.to_owned();
    meta.source = Source::Mnemonic;

    let ks = HdKeystore::new(&param.password, meta);

    let keystore = Keystore::Hd(ks);
    flush_keystore(&keystore)?;

    let meta = keystore.meta();
    let wallet = WalletResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: "MNEMONIC".to_owned(),
        accounts: vec![],
        created_at: meta.timestamp.clone(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub(crate) fn hd_store_import(data: &[u8]) -> Result<Vec<u8>> {
    let param: HdStoreImportParam =
        HdStoreImportParam::decode(data).expect("import wallet from mnemonic");

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
    let wallet = WalletResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: "MNEMONIC".to_owned(),
        accounts: vec![],
        created_at: meta.timestamp.clone(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

#[deprecated(
    since = "2.5.1",
    note = "Please use the export_mnemonic function instead"
)]
#[allow(deprecated)]
pub(crate) fn hd_store_export(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("hd_store_export");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let export_result = KeystoreCommonExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::Mnemonic as i32,
        value: guard.keystore().export()?,
    };

    encode_message(export_result)
}

fn enc_xpub(xpub: &str, network: &str) -> Result<String> {
    let xpk = Bip32DeterministicPublicKey::from_hex(xpub)?;
    let ext_pub_key: String;
    if network == "MAINNET" {
        ext_pub_key = xpk.to_ss58check_with_version(&[0x04, 0x88, 0xB2, 0x1E]);
    } else {
        ext_pub_key = xpk.to_ss58check_with_version(&[0x04, 0x35, 0x87, 0xCF]);
    }

    let key = tcx_crypto::XPUB_COMMON_KEY_128.read();
    let iv = tcx_crypto::XPUB_COMMON_IV.read();
    let key_bytes = hex::decode(&*key)?;
    let iv_bytes = hex::decode(&*iv)?;
    let encrypted = encrypt_pkcs7(&ext_pub_key.as_bytes(), &key_bytes, &iv_bytes)?;
    Ok(base64::encode(&encrypted))
}

pub(crate) fn keystore_common_derive(data: &[u8]) -> Result<Vec<u8>> {
    let param: KeystoreCommonDeriveParam =
        KeystoreCommonDeriveParam::decode(data).expect("keystore_common_derive");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let mut account_responses: Vec<AccountResponse> = vec![];

    for derivation in param.derivations {
        let account = derive_account(guard.keystore_mut(), &derivation)?;
        let enc_xpub = if account.ext_pub_key.is_empty() {
            Ok("".to_string())
        } else {
            enc_xpub(&account.ext_pub_key.to_string(), &account.network)
        }?;
        let account_rsp = AccountResponse {
            chain_type: derivation.chain_type.to_owned(),
            address: account.address.to_owned(),
            path: account.derivation_path.to_owned(),
            extended_xpub_key: enc_xpub,
        };
        account_responses.push(account_rsp);
    }

    let accounts_rsp = AccountsResponse {
        accounts: account_responses,
    };
    flush_keystore(guard.keystore())?;
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

    let export_result = KeystoreCommonExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::Mnemonic as i32,
        value: guard.keystore().export()?,
    };

    encode_message(export_result)
}

fn key_data_from_any_format_pk(pk: &str) -> Result<Vec<u8>> {
    let decoded = hex::decode(pk.to_string());
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

pub(crate) fn private_key_store_import(data: &[u8]) -> Result<Vec<u8>> {
    let param: PrivateKeyStoreImportParam =
        PrivateKeyStoreImportParam::decode(data).expect("private_key_store_import");

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
    let private_key = hex::encode(pk_bytes);
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
    let wallet = WalletResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: "PRIVATE".to_owned(),
        accounts: vec![],
        created_at: meta.timestamp.clone(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

#[deprecated(
    since = "2.5.1",
    note = "Please use the export_private_key function instead"
)]
pub(crate) fn private_key_store_export(data: &[u8]) -> Result<Vec<u8>> {
    let param: PrivateKeyStoreExportParam =
        PrivateKeyStoreExportParam::decode(data).expect("private_key_store_export");

    if NO_PK_CHAINS.contains(&param.chain_type.as_str()) {
        return Err(format_err!("chain_cannot_export_private_key"));
    }

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let pk_hex = guard.keystore().export()?;

    // private_key prefix is only about chain type and network
    let coin_info = coin_info_from_param(&param.chain_type, &param.network, "", "")?;
    let value = if param.chain_type.as_str() == "TRON" {
        Ok(pk_hex.to_string())
    } else if param.chain_type.as_str() == "TEZOS" {
        Ok(build_tezos_base58_private_key(pk_hex.as_str())?)
    } else {
        let bytes = hex::decode(pk_hex.to_string())?;
        let typed_pk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &bytes)?;
        typed_pk.fmt(&coin_info)
    }?;

    let export_result = KeystoreCommonExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::PrivateKey as i32,
        value,
    };

    encode_message(export_result)
}

pub(crate) fn export_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam =
        ExportPrivateKeyParam::decode(data).expect("export_private_key");

    // TODO: refactor using ChainFactory
    if NO_PK_CHAINS.contains(&param.chain_type.as_str()) {
        return Err(format_err!("chain_cannot_export_private_key"));
    }

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let pk_hex = if param.path.is_empty() {
        guard
            .keystore_mut()
            .export_private_key(&param.chain_type, &param.main_address, None)?
    } else {
        // get the relative path
        let mut relative_path: &str = param.path.as_str();
        if param.path.starts_with("m") {
            let acc_path = get_account_path(relative_path)?;
            relative_path = &relative_path[acc_path.len()..];
        }

        if relative_path.starts_with("/") {
            relative_path = &relative_path[1..];
        }

        guard.keystore_mut().export_private_key(
            &param.chain_type,
            &param.main_address,
            Some(relative_path),
        )?
    };

    // private_key prefix is only about chain type and network
    let value = if ["TRON", "POLKADOT", "KUSAMA"].contains(&param.chain_type.as_str()) {
        Ok(pk_hex.to_string())
    } else if "FILECOIN".contains(&param.chain_type.as_str()) {
        if let Some(account) = guard
            .keystore_mut()
            .account("FILECOIN", &param.main_address)
        {
            Ok(hex::encode(
                KeyInfo::from_private_key(account.curve, &hex::decode(pk_hex)?)?.to_json()?,
            ))
        } else {
            Err(format_err!("{}", "account_not_found"))
        }
    } else if "TEZOS".contains(&param.chain_type.as_str()) {
        Ok(build_tezos_base58_private_key(pk_hex.as_str())?)
    } else {
        // private_key prefix is only about chain type and network
        let coin_info = coin_info_from_param(&param.chain_type, &param.network, "", "")?;

        let bytes = hex::decode(pk_hex.to_string())?;
        let typed_pk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &bytes)?;
        typed_pk.fmt(&coin_info)
    }?;

    let export_result = KeystoreCommonExportResult {
        id: guard.keystore().id(),
        r#type: KeyType::PrivateKey as i32,
        value,
    };

    encode_message(export_result)
}

pub(crate) fn keystore_common_verify(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("keystore_common_delete");
    let map = KEYSTORE_MAP.read();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.password) {
        let rsp = Response {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(format_err!("{}", "password_incorrect"))
    }
}

pub(crate) fn keystore_common_delete(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("keystore_common_delete");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.password) {
        delete_keystore_file(&param.id)?;
        map.remove(&param.id);

        let rsp = Response {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(format_err!("{}", "password_incorrect"))
    }
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
    let result: KeystoreCommonExistsResult;
    if let Some(ks) = founded {
        result = KeystoreCommonExistsResult {
            is_exists: true,
            id: ks.id(),
        }
    } else {
        result = KeystoreCommonExistsResult {
            is_exists: false,
            id: "".to_owned(),
        }
    }
    encode_message(result)
}

pub(crate) fn keystore_common_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: KeystoreCommonAccountsParam =
        KeystoreCommonAccountsParam::decode(data).expect("keystore_common_accounts params");
    let map = KEYSTORE_MAP.read();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut accounts: Vec<AccountResponse> = vec![];
    for account in keystore.accounts() {
        let enc_xpub = if account.ext_pub_key.is_empty() {
            "".to_string()
        } else {
            enc_xpub(&account.ext_pub_key, &account.network)?
        };
        // let enc_xpub = enc_xpub(&account.ext_pub_key, &account.network)?;
        let acc_rsp = AccountResponse {
            chain_type: account.coin.to_owned(),
            address: account.address.to_owned(),
            path: account.derivation_path.to_owned(),
            extended_xpub_key: enc_xpub.to_owned(),
        };
        accounts.push(acc_rsp);
    }

    let accounts_rsp = AccountsResponse { accounts };
    encode_message(accounts_rsp)
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

    /*
    match param.chain_type.as_str() {
        "BITCOINCASH" | "LITECOIN" => sign_btc_fork_transaction(&param, guard.keystore_mut()),
        "TRON" => sign_tron_tx(&param, guard.keystore_mut()),
        "NERVOS" => sign_nervos_ckb(&param, guard.keystore_mut()),
        "POLKADOT" | "KUSAMA" => sign_substrate_tx_raw(&param, guard.keystore_mut()),
        "FILECOIN" => sign_filecoin_tx(&param, guard.keystore_mut()),
        "TEZOS" => sign_tezos_tx_raw(&param, guard.keystore_mut()),
        "COSMOS" => sign_cosmos_tx(&param, guard.keystore_mut()),
        "EOS" => sign_eos_tx(&param, guard.keystore_mut()),
        _ => Err(format_err!("unsupported_chain")),
    }
     */
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

    match param.chain_type.as_str() {
        "TRON" => sign_tron_message(&param, guard.keystore_mut()),
        "EOS" => sign_eos_message(&param, guard.keystore_mut()),
        _ => Err(format_err!("unsupported_chain")),
    }
}

// TODO: replacing with ChainFactory
pub(crate) fn get_public_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: PublicKeyParam = PublicKeyParam::decode(data).expect("PublicKeyParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let account = keystore.account(&param.chain_type, &param.address);
    let mut pub_key = vec![];
    if let Some(acc) = account {
        tcx_ensure!(
            acc.public_key.is_some(),
            format_err!("account_not_contains_public_key")
        );
        pub_key = hex::decode(acc.public_key.clone().unwrap())?;
    } else {
        return Err(format_err!("account_not_found"));
    }
    let mut ret = PublicKeyResult {
        id: param.id.to_string(),
        chain_type: param.chain_type.to_string(),
        address: param.address.to_string(),
        public_key: String::new(),
    };
    //https://www.rubydoc.info/gems/tezos_client/0.2.1/TezosClient/Crypto
    let edpk_prefix: Vec<u8> = vec![0x0D, 0x0F, 0x25, 0xD9];
    match param.chain_type.to_uppercase().as_str() {
        "TEZOS" => {
            let to_hash = [edpk_prefix, pub_key].concat();
            let hashed = dsha256(&to_hash);
            let hash_with_checksum = [to_hash, hashed[0..4].to_vec()].concat();
            let edpk = hash_with_checksum.to_base58();
            ret.public_key = edpk;
            encode_message(ret)
        }
        "ETHEREUM2" => {
            ret.public_key = hex::encode(pub_key);
            encode_message(ret)
        }
        _ => {
            let encoder =
                create_chain_factory(&param.chain_type.to_uppercase())?.create_public_key_encoder();
            ret.public_key = encoder.encode(&pub_key)?;
            encode_message(ret)
        }
    }
}

/*
pub(crate) fn sign_filecoin_tx(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: UnsignedMessage = UnsignedMessage::decode(
        param
            .input
            .as_ref()
            .expect("invalid_message")
            .value
            .clone()
            .as_slice(),
    )
    .expect("FilecoinTxIn");

    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
}

pub(crate) fn sign_btc_fork_transaction(
    param: &SignParam,
    keystore: &mut Keystore,
) -> Result<Vec<u8>> {
    let input: BtcKinTxInput = BtcKinTxInput::decode(
        param
            .input
            .as_ref()
            .expect("tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("BitcoinForkTransactionInput");

    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
}

pub(crate) fn sign_nervos_ckb(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: CkbTxInput = CkbTxInput::decode(
        param
            .input
            .as_ref()
            .expect("tx_iput")
            .value
            .clone()
            .as_slice(),
    )
    .expect("CkbTxInput");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
}

pub(crate) fn sign_tron_tx(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: TronTxInput = TronTxInput::decode(
        param
            .input
            .as_ref()
            .expect("tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("TronTxInput");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;

    encode_message(signed_tx)
}

pub(crate) fn sign_cosmos_tx(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: AtomTxInput = AtomTxInput::decode(
        param
            .input
            .as_ref()
            .expect("tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("AtomTxInput");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;

    encode_message(signed_tx)
}

pub(crate) fn sign_eos_tx(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input = EosTxInput::decode(
        param
            .input
            .as_ref()
            .expect("tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("EosTxInput");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;

    encode_message(signed_tx)
}
 */

pub(crate) fn sign_eos_message(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input = EosMessageInput::decode(
        param
            .input
            .as_ref()
            .expect("eos_message_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("EosMessageInput");
    let signed_message = keystore.sign_message(&param.chain_type, &param.address, &input)?;

    encode_message(signed_message)
}

pub(crate) fn sign_tron_message(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: TronMessageInput = TronMessageInput::decode(
        param
            .input
            .as_ref()
            .expect("TronMessageInput")
            .value
            .clone()
            .as_slice(),
    )
    .expect("TronMessageInput");
    let signed_message = keystore.sign_message(&param.chain_type, &param.address, &input)?;
    encode_message(signed_message)
}

#[deprecated(
    since = "2.5.1",
    note = "Please use the sign_message route function instead"
)]
pub(crate) fn sign_tron_message_legacy(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("SignParam");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = match param.key.unwrap() {
        Key::Password(password) => KeystoreGuard::unlock_by_password(keystore, &password)?,
        Key::DerivedKey(derived_key) => {
            KeystoreGuard::unlock_by_derived_key(keystore, &derived_key)?
        }
    };

    let input: TronMessageInput = TronMessageInput::decode(
        param
            .input
            .expect("TronMessageInput")
            .value
            .clone()
            .as_slice(),
    )
    .expect("TronMessageInput");
    let signed_tx = guard
        .keystore_mut()
        .sign_message(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
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

pub(crate) fn sign_substrate_tx_raw(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: SubstrateRawTxIn = SubstrateRawTxIn::decode(
        param
            .input
            .as_ref()
            .expect("raw_tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("SubstrateTxIn");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
}

pub(crate) fn import_substrate_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: SubstrateKeystoreParam = SubstrateKeystoreParam::decode(data)?;
    let ks: SubstrateKeystore = serde_json::from_str(&param.keystore)?;
    let _ = ks.validate()?;
    let pk = decode_substrate_keystore(&ks, &param.password)?;
    let pk_import_param = PrivateKeyStoreImportParam {
        private_key: hex::encode(pk),
        password: param.password.to_string(),
        name: ks.meta.name,
        password_hint: "".to_string(),
        overwrite: param.overwrite,
        encoding: "".to_string(),
    };
    let param_bytes = encode_message(pk_import_param)?;
    private_key_store_import(&param_bytes)
}

pub(crate) fn export_substrate_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam = ExportPrivateKeyParam::decode(data.clone())?;
    let meta: Metadata;
    {
        let map = KEYSTORE_MAP.read();

        let keystore: &Keystore = match map.get(&param.id) {
            Some(keystore) => Ok(keystore),
            _ => Err(format_err!("{}", "wallet_not_found")),
        }?;

        // !!! Warning !!! HDKeystore only can export raw sr25519 key,
        // but polkadotjs keystore needs a Ed25519 expanded secret key.
        if keystore.derivable() {
            return Err(format_err!("{}", "hd_wallet_cannot_export_keystore"));
        }
        meta = keystore.meta().clone();
    }

    let ret = export_private_key(data)?;
    let export_result: KeystoreCommonExportResult =
        KeystoreCommonExportResult::decode(ret.as_slice())?;
    let pk = export_result.value;
    let pk_bytes = hex::decode(pk)?;
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

pub(crate) fn substrate_keystore_exists(data: &[u8]) -> Result<Vec<u8>> {
    let param: SubstrateKeystoreParam = SubstrateKeystoreParam::decode(data)?;
    let ks: SubstrateKeystore = serde_json::from_str(&param.keystore)?;
    let _ = ks.validate()?;
    let pk = decode_substrate_keystore(&ks, &param.password)?;

    let pk_hex = hex::encode(&pk);
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

pub(crate) fn sign_tezos_tx_raw(param: &SignParam, keystore: &mut Keystore) -> Result<Vec<u8>> {
    let input: TezosRawTxIn = TezosRawTxIn::decode(
        param
            .input
            .as_ref()
            .expect("raw_tx_input")
            .value
            .clone()
            .as_slice(),
    )
    .expect("TezosRawTxIn");
    let signed_tx = keystore.sign_transaction(&param.chain_type, &param.address, &input)?;
    encode_message(signed_tx)
}

pub(crate) fn zksync_private_key_from_seed(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncPrivateKeyFromSeedParam = ZksyncPrivateKeyFromSeedParam::decode(data)?;

    let result = private_key_from_seed(hex::decode(param.seed)?.as_slice())
        .expect("zksync_private_key_from_seed_error");

    let ret = ZksyncPrivateKeyFromSeedResult {
        priv_key: hex::encode(result),
    };
    encode_message(ret)
}

pub(crate) fn zksync_sign_musig(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncSignMusigParam = ZksyncSignMusigParam::decode(data)?;

    let sign_result = sign_musig(
        hex::decode(param.priv_key)?.as_slice(),
        hex::decode(param.bytes)?.as_slice(),
    )
    .expect("zksync_sign_musig_error");
    let ret = ZksyncSignMusigResult {
        signature: hex::encode(sign_result),
    };
    encode_message(ret)
}

pub(crate) fn zksync_private_key_to_pubkey_hash(data: &[u8]) -> Result<Vec<u8>> {
    let param: ZksyncPrivateKeyToPubkeyHashParam = ZksyncPrivateKeyToPubkeyHashParam::decode(data)?;
    let pub_key_hash = private_key_to_pubkey_hash(hex::decode(param.priv_key)?.as_slice())
        .expect("zksync_private_key_to_pubkey_hash_error");
    let ret = ZksyncPrivateKeyToPubkeyHashResult {
        pub_key_hash: hex::encode(pub_key_hash),
    };
    encode_message(ret)
}

pub(crate) fn sign_bls_to_execution_change(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignBlsToExecutionChangeParam = SignBlsToExecutionChangeParam::decode(data)?;
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;
    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;
    let result: SignBlsToExecutionChangeResult =
        param.sign_bls_to_execution_change(guard.keystore_mut())?;
    encode_message(result)
}

pub(crate) fn generate_mnemonic() -> Result<Vec<u8>> {
    let mnemonic = tcx_primitive::generate_mnemonic();
    let result = GenerateMnemonicResult { mnemonic };
    encode_message(result)
}

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

pub(crate) fn sign_transaction(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("SignTxParam");

    let keystore = IMTKeystore::must_find_wallet_by_id(&param.id)?;
    let password = match param.key.clone().unwrap() {
        Key::Password(password) => password,
        _ => {
            return Err(format_err!("key_type_error"));
        }
    };

    let private_key = keystore.decrypt_main_key(password.as_str())?;

    let result = match param.chain_type.as_str() {
        "ETHEREUM" => sign_eth_transaction(&param, private_key.as_slice()),
        _ => Err(format_err!("unsupported_chain")),
    }?;

    Ok(result)
}

pub(crate) fn sign_eth_transaction(param: &SignParam, private_key: &[u8]) -> Result<Vec<u8>> {
    todo!()
    /*
    let eth_tx_input: EthTxInput = EthTxInput::decode(
        param
            .input
            .as_ref()
            .expect("eth_tx_input_error")
            .value
            .clone()
            .as_slice(),
    )
    .expect("EthereumTransactionInputError");

    if !tcx_eth::address::is_valid_address(&eth_tx_input.to) {
        return Err(format_err!("invalid_to_address"));
    }

    let eth_tx_output: Result<EthTxOutput> =
        task::block_on(async { eth_tx_input.sign_transaction(private_key).await });
    encode_message(eth_tx_output?)

     */
}

pub(crate) fn eth_sign_message(data: &[u8]) -> Result<Vec<u8>> {
    todo!()
    /*
    let param: SignParam = SignParam::decode(data).expect("EthPersonalSignParam");

    let keystore = IMTKeystore::must_find_wallet_by_id(&param.id)?;
    let password = match param.key.clone().unwrap() {
        Key::Password(password) => password,
        _ => {
            return Err(format_err!("key_type_error"));
        }
    };

    let private_key = keystore.decrypt_main_key(password.as_str())?;

    let input: EthMessageInput = EthMessageInput::decode(
        param
            .input
            .expect("EthMessageInput")
            .value
            .clone()
            .as_slice(),
    )?;
    let sign_result: Result<EthMessageOutput> =
        task::block_on(async { input.sign_message(private_key.as_slice()).await });

    encode_message(sign_result?)
     */
}

pub(crate) fn eth_ec_sign(data: &[u8]) -> Result<Vec<u8>> {
    todo!()
    /*
    let param: SignParam = SignParam::decode(data).expect("EthMessageSignParam");

    let keystore = IMTKeystore::must_find_wallet_by_id(&param.id)?;
    let password = match param.key.clone().unwrap() {
        Key::Password(password) => password,
        _ => {
            return Err(format_err!("key_type_error"));
        }
    };

    let private_key = keystore.decrypt_main_key(password.as_str())?;

    let input: EthMessageInput = EthMessageInput::decode(
        param
            .input
            .expect("EthMessageInput")
            .value
            .clone()
            .as_slice(),
    )?;
    let sign_result: Result<EthMessageOutput> =
        task::block_on(async { input.ec_sign(private_key.as_slice()).await });

    encode_message(sign_result?)

     */
}

pub(crate) fn eth_recover_address(data: &[u8]) -> Result<Vec<u8>> {
    let input: EthRecoverAddressInput =
        EthRecoverAddressInput::decode(data).expect("EthRecoverAddressParam");
    let result: Result<EthRecoverAddressOutput> = input.recover_address();

    encode_message(result?)
}

pub(crate) fn eos_update_account(data: &[u8]) -> Result<Vec<u8>> {
    let param: KeystoreUpdateAccount =
        KeystoreUpdateAccount::decode(data).expect("eos_update_account params");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    // todo: use ErrorKind
    tcx_ensure!(
        keystore.verify_password(&param.password),
        format_err!("password_incorrect")
    );

    tcx_eos::address::eos_update_account(keystore, &param.account_name)?;
    flush_keystore(&keystore)?;
    let rsp = Response {
        is_success: true,
        error: "".to_string(),
    };
    encode_message(rsp)
}

pub(crate) fn eth_v3keystore_import(data: &[u8]) -> Result<Vec<u8>> {
    let input: V3KeystoreImportInput =
        V3KeystoreImportInput::decode(data).expect("V3KeystoreImportInput");
    let v3_keystore = import_wallet_from_keystore(input)?;
    let metadata = v3_keystore.im_token_meta.unwrap();
    let ret_wallet: WalletResult = WalletResult {
        id: v3_keystore.id,
        created_at: metadata.timestamp as i64,
        source: metadata.source,
        name: metadata.name,
        accounts: vec![],
    };
    encode_message(ret_wallet)
}

pub(crate) fn eth_v3keystore_export(data: &[u8]) -> Result<Vec<u8>> {
    let input: V3KeystoreExportInput =
        V3KeystoreExportInput::decode(data).expect("V3KeystoreExportInput");
    let keystore = IMTKeystore::must_find_wallet_by_id(&input.id)?;
    let json = keystore.export_keystore(&input.password)?;
    let output = V3KeystoreExportOutput { json };
    encode_message(output)
}
