use base58::ToBase58;
use bytes::BytesMut;
use prost::Message;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use tcx_eos::address::EosAddress;
use tcx_eos::encode_eos_wif;
use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
use tcx_keystore::keystore::IdentityNetwork;

use tcx_common::{sha256d, FromHex, ToHex};
use tcx_primitive::{
    private_key_without_version, PrivateKey, PublicKey, Secp256k1PrivateKey, Secp256k1PublicKey,
    Sr25519PrivateKey, TypedPrivateKey, TypedPublicKey,
};

use tcx_btc_kin::WIFDisplay;
use tcx_keystore::{
    fingerprint_from_mnemonic, fingerprint_from_private_key, Address, Keystore, KeystoreGuard,
    SignatureParameters, Signer,
};
use tcx_keystore::{Account, HdKeystore, Metadata, PrivateKeystore, Source};

use tcx_crypto::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
use tcx_filecoin::KeyInfo;

use crate::api::derive_accounts_param::Derivation;
use crate::api::sign_param::Key;
use crate::api::{
    AccountResponse, CreateKeystoreParam, DecryptDataFromIpfsParam, DecryptDataFromIpfsResult,
    DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
    DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExistsJsonParam,
    ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam, ExportJsonParam,
    ExportJsonResult, ExportMnemonicResult, ExportPrivateKeyParam, ExportPrivateKeyResult,
    GeneralResult, GetExtendedPublicKeysParam, GetExtendedPublicKeysResult, GetPublicKeysParam,
    GetPublicKeysResult, ImportJsonParam, ImportMnemonicParam, ImportPrivateKeyParam,
    ImportPrivateKeyResult, KeystoreMigrationParam, KeystoreResult, MnemonicToPublicKeyParam,
    MnemonicToPublicKeyResult, RemoveWalletParam, RemoveWalletResult,
    SignAuthenticationMessageParam, SignAuthenticationMessageResult, SignHashesParam,
    SignHashesResult, WalletKeyParam,
};
use crate::api::{InitTokenCoreXParam, SignParam};
use crate::error_handling::Result;
use crate::filemanager::{
    self, cache_keystore, clean_keystore, copy_to_v2_if_need, flush_keystore, KEYSTORE_BASE_DIR,
    WALLET_FILE_DIR, WALLET_V2_DIR,
};
use crate::filemanager::{delete_keystore_file, KEYSTORE_MAP};

use crate::IS_DEBUG;

use base58::FromBase58;
use tcx_keystore::tcx_ensure;

use tcx_constants::coin_info::coin_info_from_param;
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};
use tcx_crypto::KDF_ROUNDS;
use tcx_eth::transaction::{EthRecoverAddressInput, EthRecoverAddressOutput};
use tcx_keystore::{MessageSigner, TransactionSigner};
use tcx_migration::keystore_upgrade::KeystoreUpgrade;

use tcx_primitive::{Bip32DeterministicPublicKey, Ss58Codec};
use tcx_substrate::{decode_substrate_keystore, encode_substrate_keystore, SubstrateKeystore};

use tcx_migration::migration::LegacyKeystore;
use tcx_primitive::TypedDeterministicPublicKey;
use tcx_tezos::{build_tezos_base58_private_key, parse_tezos_private_key};

use crate::macros::use_chains;

use_chains!(
    tcx_btc_kin::bitcoin,
    tcx_btc_kin::omni,
    tcx_btc_kin::bitcoincash,
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

fn key_data_from_any_format_pk(pk: &str) -> Result<Vec<u8>> {
    let decoded = Vec::from_hex_auto(pk.to_string());
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

fn fingerprint_from_any_format_pk(pk: &str) -> Result<String> {
    let key_data = key_data_from_any_format_pk(pk)?;
    fingerprint_from_private_key(&key_data)
}

fn fingerprint_from_tezos_format_pk(pk: &str) -> Result<String> {
    let key_data = parse_tezos_private_key(pk)?;
    fingerprint_from_private_key(&key_data)
}

fn import_private_key_internal(
    param: &ImportPrivateKeyParam,
    source: Option<Source>,
) -> Result<ImportPrivateKeyResult> {
    let mut founded_id: Option<String> = None;
    {
        let fingerprint: String;
        if param.private_key.starts_with("edsk") {
            fingerprint = fingerprint_from_tezos_format_pk(&param.private_key)?;
        } else {
            fingerprint = fingerprint_from_any_format_pk(&param.private_key)?;
        }
        let map = KEYSTORE_MAP.read();
        if let Some(founded) = map
            .values()
            .find(|keystore| keystore.fingerprint() == fingerprint)
        {
            founded_id = Some(founded.id());
        }
    }

    if founded_id.is_some() && !param.overwrite {
        return Err(format_err!("{}", "address_already_exist"));
    }

    let decoded_ret = decode_private_key(&param.private_key)?;
    let private_key = decoded_ret.bytes.to_hex();
    let meta_source = if let Some(source) = source {
        source
    } else {
        decoded_ret.source
    };
    let meta = Metadata {
        name: param.name.to_string(),
        password_hint: param.password_hint.to_string(),
        source: meta_source,
        ..Metadata::default()
    };
    let pk_store = PrivateKeystore::from_private_key(&private_key, &param.password, meta)?;

    let mut keystore = Keystore::PrivateKey(pk_store);

    if let Some(exist_kid) = founded_id {
        keystore.set_id(&exist_kid)
    }

    flush_keystore(&keystore)?;

    let meta = keystore.meta();
    let identity = keystore.identity();
    let wallet = ImportPrivateKeyResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: meta_source.to_string(),
        created_at: meta.timestamp.clone(),
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
        suggest_chain_types: decoded_ret.chain_types.to_owned(),
        suggest_network: decoded_ret.network.to_string(),
        suggest_curve: decoded_ret.curve.as_str().to_string(),
        source_finger_print: keystore.fingerprint().to_string(),
    };
    cache_keystore(keystore);
    Ok(wallet)
}

struct DecodedPrivateKey {
    bytes: Vec<u8>,
    network: String,
    curve: CurveType,
    chain_types: Vec<String>,
    source: Source,
}

fn decode_private_key(private_key: &str) -> Result<DecodedPrivateKey> {
    let private_key_bytes: Vec<u8>;
    let mut network = "".to_string();
    let mut chain_types: Vec<String> = vec![];
    let mut curve: CurveType = CurveType::SECP256k1;
    let mut source: Source = Source::Private;
    if private_key.starts_with("edsk") {
        private_key_bytes = parse_tezos_private_key(&private_key)?;
        chain_types.push("TEZOS".to_string());
    } else {
        let decoded = Vec::from_hex_auto(private_key.to_string());
        if decoded.is_ok() {
            let decoded_data = decoded.unwrap();
            if decoded_data.len() == 32 {
                private_key_bytes = decoded_data;
                chain_types.push("ETHEREUM".to_string());
                chain_types.push("TRON".to_string());
            } else if decoded_data.len() == 64 {
                let sr25519_key = Sr25519PrivateKey::from_slice(&decoded_data)?;
                private_key_bytes = sr25519_key.to_bytes();
                chain_types.push("KUSAMA".to_string());
                chain_types.push("POLKADOT".to_string());
                curve = CurveType::SR25519;
            } else {
                let key_info = KeyInfo::from_lotus(&decoded_data)?;
                private_key_bytes = key_info.decode_private_key()?;
                chain_types.push("FILECOIN".to_string());
                if key_info.r#type != "secp256k1" {
                    curve = CurveType::BLS;
                }
            }
        } else {
            let data_len = private_key
                .from_base58()
                .map_err(|_| format_err!("decode private from base58 error"))?
                .len();
            let (k1_pk, ver) = Secp256k1PrivateKey::from_ss58check_with_version(&private_key)?;
            private_key_bytes = k1_pk.0.to_bytes();

            source = Source::Wif;
            match ver[0] {
                0xef => {
                    network = "TESTNET".to_string();
                    chain_types.push("BITCOIN".to_string());
                    chain_types.push("BITCOINCASH".to_string());
                    chain_types.push("LITECOIN".to_string());
                }
                0x80 => {
                    if data_len == 37 {
                        // EOS 1byte network + 32bytes private key + 4byte checksum = 37bytes
                        // EOS not use compressed suffix  https://developers.eos.io/manuals/eos/v2.2/keosd/wallet-specification
                        network = "".to_string();
                        chain_types.push("EOS".to_string());
                    } else {
                        // EOS 1byte network + 32bytes private key + 1byte compressed suffix + 4byte checksum = 38bytes
                        network = "MAINNET".to_string();
                        chain_types.push("BITCOIN".to_string());
                        chain_types.push("BITCOINCASH".to_string());
                    }
                }
                0xb0 => {
                    network = "MAINNET".to_string();
                    chain_types.push("LITECOIN".to_string());
                }
                _ => {
                    return Err(format_err!(
                        "unknow ver header when parse wif, ver: {}",
                        ver[0]
                    ))
                }
            }
        }
    }

    Ok(DecodedPrivateKey {
        bytes: private_key_bytes,
        network,
        curve,
        chain_types,
        source,
    })
}

fn exists_fingerprint(fingerprint: &str) -> Result<Vec<u8>> {
    let map = &KEYSTORE_MAP.read();

    let founded: Option<&Keystore> = map
        .values()
        .find(|keystore| keystore.fingerprint() == fingerprint);
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

fn key_info_from_v3(keystore: &str, password: &str) -> Result<(Vec<u8>, String)> {
    let ks: LegacyKeystore = serde_json::from_str(&keystore)?;
    ks.validate_v3(&password)?;
    let key = tcx_crypto::Key::Password(password.to_string());
    let unlocker = ks.crypto.use_key(&key)?;
    let pk = unlocker.plaintext()?;
    return Ok((pk, "Imported ETH".to_string()));
}

fn key_info_from_substrate_keystore(keystore: &str, password: &str) -> Result<(Vec<u8>, String)> {
    let ks: SubstrateKeystore = serde_json::from_str(&keystore)?;
    let _ = ks.validate()?;
    let pk = decode_substrate_keystore(&ks, &password)?;
    return Ok((pk, ks.meta.name));
}

pub fn init_token_core_x(data: &[u8]) -> Result<()> {
    let InitTokenCoreXParam {
        file_dir,
        xpub_common_key,
        xpub_common_iv,
        is_debug,
    } = InitTokenCoreXParam::decode(data).unwrap();
    *KEYSTORE_BASE_DIR.write() = file_dir.to_string();
    copy_to_v2_if_need()?;

    *WALLET_FILE_DIR.write() = format!("{}/{}", file_dir, WALLET_V2_DIR);

    *XPUB_COMMON_KEY_128.write() = xpub_common_key.to_string();
    *XPUB_COMMON_IV.write() = xpub_common_iv.to_string();

    if is_debug {
        *IS_DEBUG.write() = is_debug;
        if is_debug {
            *KDF_ROUNDS.write() = 1;
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
        CreateKeystoreParam::decode(data).expect("create_keystore param");

    let mut meta = Metadata::default();
    meta.name = param.name.to_owned();
    meta.password_hint = param.password_hint.to_owned();
    meta.source = Source::NewMnemonic;
    meta.network = IdentityNetwork::from_str(&param.network)?;

    let ks = HdKeystore::new(&param.password, meta);

    let keystore = Keystore::Hd(ks);
    flush_keystore(&keystore)?;

    let identity = keystore.identity();

    let meta = keystore.meta();
    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: Source::NewMnemonic.to_string(),
        created_at: meta.timestamp.clone(),
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
        source_finger_print: keystore.fingerprint().to_string(),
    };

    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub(crate) fn import_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ImportMnemonicParam =
        ImportMnemonicParam::decode(data).expect("import_mnemonic param");

    let mut founded_id: Option<String> = None;
    {
        let fingerprint = fingerprint_from_mnemonic(&param.mnemonic)?;
        let map = KEYSTORE_MAP.read();
        if let Some(founded) = map
            .values()
            .find(|keystore| keystore.fingerprint() == fingerprint)
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
        source_finger_print: keystore.fingerprint().to_string(),
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub(crate) fn derive_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveAccountsParam =
        DeriveAccountsParam::decode(data).expect("derive_accounts param");
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
            encrypt_xpub(&account.ext_pub_key.to_string(), &account.network)
        }?;
        let account_rsp = AccountResponse {
            chain_type: derivation.chain_type.to_owned(),
            address: account.address.to_owned(),
            path: account.derivation_path.to_owned(),
            curve: account.curve.as_str().to_string(),
            public_key: account.public_key,
            extended_public_key: account.ext_pub_key.to_string(),
            encrypted_extended_public_key: enc_xpub,
        };
        account_responses.push(account_rsp);
    }

    let accounts_rsp = DeriveAccountsResult {
        accounts: account_responses,
    };
    encode_message(accounts_rsp)
}

pub(crate) fn export_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("export_mnemonic param");
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

    let export_result = ExportMnemonicResult {
        id: guard.keystore().id(),
        mnemonic: guard.keystore().export()?,
    };

    encode_message(export_result)
}

pub(crate) fn import_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ImportPrivateKeyParam =
        ImportPrivateKeyParam::decode(data).expect("import_private_key param");

    let rsp = import_private_key_internal(&param, None)?;

    let ret = encode_message(rsp)?;
    Ok(ret)
}

pub(crate) fn export_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam =
        ExportPrivateKeyParam::decode(data).expect("export_private_key param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;

    let curve = CurveType::from_str(&param.curve);
    let private_key_bytes = guard
        .keystore_mut()
        .get_private_key(curve, &param.path)?
        .to_bytes();

    let value = if ["TRON", "POLKADOT", "KUSAMA", "ETHEREUM"].contains(&param.chain_type.as_str()) {
        Ok(private_key_bytes.to_0x_hex())
    } else if "FILECOIN".contains(&param.chain_type.as_str()) {
        Ok(KeyInfo::from_private_key(curve, &private_key_bytes)?
            .to_json()?
            .to_hex())
    } else if "TEZOS".contains(&param.chain_type.as_str()) {
        Ok(build_tezos_base58_private_key(&private_key_bytes.to_hex())?)
    } else if "EOS".contains(&param.chain_type) {
        encode_eos_wif(&private_key_bytes)
    } else {
        // private_key prefix is only about chain type and network
        let coin_info = coin_info_from_param(&param.chain_type, &param.network, "", "")?;
        let typed_pk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &private_key_bytes)?;
        typed_pk.fmt(&coin_info)
    }?;

    let export_result = ExportPrivateKeyResult {
        id: guard.keystore().id(),
        private_key: value,
    };

    encode_message(export_result)
}

pub(crate) fn verify_password(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("verify_password param");
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
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("delete_keystore param");
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
        ExistsPrivateKeyParam::decode(data).expect("exists_private_key param");
    let fingerprint = if param.private_key.starts_with("edsk") {
        fingerprint_from_tezos_format_pk(&param.private_key)?
    } else {
        fingerprint_from_any_format_pk(&param.private_key)?
    };
    exists_fingerprint(&fingerprint)
}

pub(crate) fn exists_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsMnemonicParam =
        ExistsMnemonicParam::decode(data).expect("exists_mnemonic param");

    let key_hash = fingerprint_from_mnemonic(&param.mnemonic)?;

    exists_fingerprint(&key_hash)
}

pub(crate) fn sign_tx(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("sign_tx param");

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
    let param: SignHashesParam = SignHashesParam::decode(data).expect("sign_hashes param");

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
    let param: GetPublicKeysParam =
        GetPublicKeysParam::decode(data).expect("get_public_keys param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock_by_password(keystore, &param.password)?;
    let public_keys: Vec<Vec<u8>> = param
        .derivations
        .iter()
        .map(|derivation| {
            let public_key = guard
                .keystore_mut()
                .get_public_key(CurveType::from_str(&derivation.curve), &derivation.path)
                .expect("PublicKeyProcessed");
            public_key.to_bytes()
        })
        .collect();

    let mut public_key_strs: Vec<String> = vec![];
    for idx in 0..param.derivations.len() {
        let pub_key = public_keys[idx].to_vec();
        let public_key_str_ret: Result<String> = match param.derivations[idx].chain_type.as_str() {
            "TEZOS" => {
                let edpk_prefix: Vec<u8> = vec![0x0D, 0x0F, 0x25, 0xD9];
                let to_hash = [edpk_prefix, pub_key].concat();
                let hashed = sha256d(&to_hash);
                let hash_with_checksum = [to_hash, hashed[0..4].to_vec()].concat();
                let edpk = hash_with_checksum.to_base58();
                Ok(edpk)
            }
            "EOS" => {
                let secp256k1_pub_key = Secp256k1PublicKey::from_slice(&pub_key)?;
                let typed_pub_key = TypedPublicKey::Secp256k1(secp256k1_pub_key);
                let eos_addr = EosAddress::from_public_key(
                    &typed_pub_key,
                    &CoinInfo {
                        coin: "EOS".to_string(),
                        curve: CurveType::SECP256k1,
                        ..Default::default()
                    },
                )?;
                Ok(eos_addr.to_string())
            }
            _ => Ok(pub_key.to_0x_hex()),
        };
        let pub_key_str = public_key_str_ret?;
        public_key_strs.push(pub_key_str);
    }

    encode_message(GetPublicKeysResult {
        public_keys: public_key_strs,
    })
}

pub(crate) fn get_extended_public_keys(data: &[u8]) -> Result<Vec<u8>> {
    let param: GetExtendedPublicKeysParam =
        GetExtendedPublicKeysParam::decode(data).expect("get_extended_public_keys param");

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
    let param: SignParam = SignParam::decode(data).expect("sign_message param");

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
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("get_derived_key param");
    let mut map: parking_lot::lock_api::RwLockWriteGuard<
        '_,
        parking_lot::RawRwLock,
        std::collections::HashMap<String, Keystore>,
    > = KEYSTORE_MAP.write();
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
    let param: ImportJsonParam = ImportJsonParam::decode(data).expect("import_json param");
    if let Ok(parse_v3_result) = key_info_from_v3(&param.json, &param.password) {
        let (sec_key_bytes, name) = parse_v3_result;
        let pk_import_param = ImportPrivateKeyParam {
            private_key: sec_key_bytes.to_hex(),
            password: param.password.to_string(),
            name,
            password_hint: "".to_string(),
            overwrite: param.overwrite,
        };
        let mut ret = import_private_key_internal(&pk_import_param, Some(Source::KeystoreV3))?;
        ret.suggest_chain_types = vec!["ETHEREUM".to_string()];
        ret.suggest_curve = CurveType::SECP256k1.as_str().to_string();
        ret.suggest_network = "".to_string();
        return encode_message(ret);
    } else if let Ok(parse_substrate_result) =
        key_info_from_substrate_keystore(&param.json, &param.password)
    {
        let (sec_key_bytes, name) = parse_substrate_result;
        let pk_import_param = ImportPrivateKeyParam {
            private_key: sec_key_bytes.to_hex(),
            password: param.password.to_string(),
            name,
            password_hint: "".to_string(),
            overwrite: param.overwrite,
        };
        let mut ret =
            import_private_key_internal(&pk_import_param, Some(Source::SubstrateKeystore))?;
        ret.suggest_chain_types = vec!["KUSAMA".to_string(), "POLKADOT".to_string()];
        ret.suggest_curve = CurveType::SR25519.as_str().to_string();
        ret.suggest_network = "".to_string();
        return encode_message(ret);
    } else {
        return Err(format_err!("unsupport_chain"));
    }
}

pub(crate) fn export_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportJsonParam = ExportJsonParam::decode(data).expect("export_json param");
    let meta: Metadata;
    {
        let map = KEYSTORE_MAP.read();

        let keystore: &Keystore = match map.get(&param.id) {
            Some(keystore) => Ok(keystore),
            _ => Err(format_err!("{}", "wallet_not_found")),
        }?;

        // !!! Warning !!! HDKeystore only can export raw sr25519 key,
        // but polkadotjs fixtures needs a Ed25519 expanded secret key.
        // they will generate difference account address
        if ["POLKADOT".to_string(), "KUSAMA".to_string()].contains(&param.chain_type)
            && keystore.derivable()
        {
            return Err(format_err!(
                "{}",
                "hd_wallet_cannot_export_substrate_keystore"
            ));
        }
        meta = keystore.meta().clone();
    }

    let curve = if ["POLKADOT".to_string(), "KUSAMA".to_string()].contains(&param.chain_type) {
        CurveType::SR25519.as_str().to_string()
    } else {
        CurveType::SECP256k1.as_str().to_string()
    };

    let export_pivate_key_param = ExportPrivateKeyParam {
        id: param.id.to_string(),
        password: param.password.to_string(),
        chain_type: param.chain_type.to_string(),
        network: "".to_string(),
        curve: curve,
        path: param.path.to_string(),
    };

    let ret = export_private_key(&encode_message(export_pivate_key_param)?)?;
    let export_result: ExportPrivateKeyResult = ExportPrivateKeyResult::decode(ret.as_slice())?;
    let private_key = export_result.private_key;
    let private_key_bytes = Vec::from_hex_auto(private_key)?;

    let coin = coin_info_from_param(&param.chain_type, "", "", "")?;

    let json_str = match param.chain_type.as_str() {
        "KUSAMA" | "SUBSTRATE" | "POLKADOT" => {
            let mut substrate_ks =
                encode_substrate_keystore(&param.password, &private_key_bytes, &coin)?;

            substrate_ks.meta.name = meta.name;
            substrate_ks.meta.when_created = meta.timestamp;
            serde_json::to_string(&substrate_ks)?
        }
        "ETHEREUM" => {
            let keystore = LegacyKeystore::new_v3(&private_key_bytes, &param.password)?;
            serde_json::to_string(&keystore)?
        }
        _ => return Err(format_err!("unsupported_chain")),
    };

    let ret = ExportJsonResult {
        id: param.id.to_string(),
        json: json_str,
    };
    return encode_message(ret);
}

pub(crate) fn exists_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsJsonParam = ExistsJsonParam::decode(data).expect("exists_json param");

    let sec_key_hex = if let Ok(parse_v3_result) = key_info_from_v3(&param.json, &param.password) {
        let (sec_key_bytes, _) = parse_v3_result;
        sec_key_bytes.to_hex()
    } else if let Ok(parse_substrate_result) =
        key_info_from_substrate_keystore(&param.json, &param.password)
    {
        let (sec_key_bytes, _) = parse_substrate_result;
        sec_key_bytes.to_hex()
    } else {
        return Err(format_err!("decrypt_json_error"));
    };

    let exists_param = ExistsPrivateKeyParam {
        private_key: sec_key_hex,
    };
    let exists_param_bytes = encode_message(exists_param)?;
    exists_private_key(&exists_param_bytes)
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

pub(crate) fn remove_wallet(data: &[u8]) -> Result<Vec<u8>> {
    let param: RemoveWalletParam = RemoveWalletParam::decode(data)?;
    let map = KEYSTORE_MAP.read();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(format_err!("{}", "wallet_not_found")),
    }?;

    if !keystore.verify_password(&param.password) {
        return Err(failure::format_err!("password_incorrect"));
    }
    filemanager::delete_keystore_file(&param.id)?;

    let result = RemoveWalletResult { is_success: true };
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
    // TODO: hide crypto object
    let unlocker = identity_ks.store().crypto.use_key(&key)?;

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

pub(crate) fn derive_sub_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveSubAccountsParam =
        DeriveSubAccountsParam::decode(data).expect("DeriveSubAccountsParam");

    let curve = CurveType::from_str(&param.curve);
    let xpub = TypedDeterministicPublicKey::from_hex(curve, &param.extended_public_key)?;

    let account_ret: Vec<Result<AccountResponse>> = param
        .relative_paths
        .iter()
        .map(|relative_path| {
            let coin_info = CoinInfo {
                coin: param.chain_type.to_string(),
                derivation_path: relative_path.to_string(),
                curve,
                network: param.network.to_string(),
                seg_wit: param.seg_wit.to_string(),
            };
            let acc: Account = derive_sub_account(&xpub, &coin_info)?;

            let enc_xpub = encrypt_xpub(&param.extended_public_key.to_string(), &acc.network)?;

            let acc_rsp = AccountResponse {
                chain_type: param.chain_type.to_string(),
                address: acc.address.to_string(),
                path: relative_path.to_string(),
                extended_public_key: param.extended_public_key.to_string(),
                encrypted_extended_public_key: enc_xpub,
                public_key: acc.public_key,
                curve: param.curve.to_string(),
            };
            Ok(acc_rsp)
        })
        .collect();

    let accounts: Vec<AccountResponse> = account_ret
        .into_iter()
        .collect::<Result<Vec<AccountResponse>>>()?;

    encode_message(DeriveSubAccountsResult { accounts })
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
            source_finger_print: keystore.fingerprint().to_string(),
        });

        cache_keystore(keystore);
        ret
    } else {
        Err(format_err!("invalid version in keystore"))
    }
}

pub(crate) fn mnemonic_to_public(data: &[u8]) -> Result<Vec<u8>> {
    let param = MnemonicToPublicKeyParam::decode(data)?;
    let public_key = tcx_primitive::mnemonic_to_public(&param.mnemonic, &param.path, &param.curve)?;
    let public_key_str = match param.encoding.to_uppercase().as_str() {
        "EOS" => EosAddress::from_public_key(&public_key, &CoinInfo::default())?.to_string(),
        _ => public_key.to_bytes().to_0x_hex(),
    };
    encode_message(MnemonicToPublicKeyResult {
        public_key: public_key_str,
    })
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

#[cfg(test)]
mod tests {
    use tcx_constants::CurveType;
    use tcx_keystore::Source;

    use super::decode_private_key;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_decode_private_key() {
        let private_key = "cPrsVCDgzf7FLG2NyCrfudbAav4DQt2vs1ZcAqcjZWQ6wi1kp3Uc";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(
            decoded.chain_types,
            vec![
                "BITCOIN".to_string(),
                "BITCOINCASH".to_string(),
                "LITECOIN".to_string()
            ]
        );
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "TESTNET".to_string());
        assert_eq!(decoded.source, Source::Wif);

        let private_key = "KyVt2HDqZbQzApZ7ao3YYK66xgkokRwEnyR94RAE4Pk6gxtMdsrA";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(
            decoded.chain_types,
            vec!["BITCOIN".to_string(), "BITCOINCASH".to_string()]
        );
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "MAINNET".to_string());
        assert_eq!(decoded.source, Source::Wif);

        let private_key = "T5L9U2X1xyPawfBz8RzQkfdUuYQ7pWx8cBKPvDnmdMvGCrR7TZEw";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(decoded.chain_types, vec!["LITECOIN".to_string()]);
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "MAINNET".to_string());
        assert_eq!(decoded.source, Source::Wif);

        let private_key = "edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(decoded.chain_types, vec!["TEZOS".to_string()]);
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Private);

        let private_key = "0x43fe394358d14f2e096f4efe80894b4e51a3fdcb73c06b77e937b80deb8c746b";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(
            decoded.chain_types,
            vec!["ETHEREUM".to_string(), "TRON".to_string()]
        );
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Private);

        let private_key = "0x7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f354a6754767776725a774c5061513758326d4b4c6a386e4478634e685a6b537667315564434a317866593d227d";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(decoded.chain_types, vec!["FILECOIN".to_string()]);
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Private);

        let private_key = "0x7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(decoded.chain_types, vec!["FILECOIN".to_string()]);
        assert_eq!(decoded.curve, CurveType::BLS);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Private);

        let private_key = "5JLENb318PJDVxdjGp8pvmRigMLSYbCPA4GSPXPwANvGLZE3ukq";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(decoded.chain_types, vec!["EOS".to_string()]);
        assert_eq!(decoded.curve, CurveType::SECP256k1);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Wif);
    }
}
