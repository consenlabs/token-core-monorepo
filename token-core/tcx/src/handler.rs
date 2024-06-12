use bytes::BytesMut;
use prost::Message;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use tcx_eos::encode_eos_wif;
use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
use tcx_keystore::keystore::IdentityNetwork;
use tcx_migration::legacy_ipfs;

use tcx_common::{FromHex, ToHex};
use tcx_primitive::{
    private_key_without_version, PrivateKey, Secp256k1PrivateKey, Sr25519PrivateKey,
    TypedPrivateKey, TypedPublicKey,
};

use tcx_btc_kin::WIFDisplay;
use tcx_keystore::{
    fingerprint_from_mnemonic, fingerprint_from_private_key, identity, Keystore, KeystoreGuard,
    SignatureParameters, Signer,
};
use tcx_keystore::{Account, HdKeystore, Metadata, PrivateKeystore, Source};

use anyhow::{anyhow, ensure};
use tcx_crypto::{XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
use tcx_filecoin::KeyInfo;

use crate::api::derive_accounts_param::Derivation;
use crate::api::{
    self, export_private_key_param, AccountResponse, BackupResult, CreateKeystoreParam,
    DecryptDataFromIpfsParam, DecryptDataFromIpfsResult, DeriveAccountsParam, DeriveAccountsResult,
    DeriveSubAccountsParam, DeriveSubAccountsResult, DerivedKeyResult, EncryptDataToIpfsParam,
    EncryptDataToIpfsResult, ExistsJsonParam, ExistsKeystoreResult, ExistsMnemonicParam,
    ExistsPrivateKeyParam, ExportJsonParam, ExportJsonResult, ExportMnemonicParam,
    ExportMnemonicResult, ExportPrivateKeyParam, ExportPrivateKeyResult, GeneralResult,
    GetExtendedPublicKeysParam, GetExtendedPublicKeysResult, GetPublicKeysParam,
    GetPublicKeysResult, ImportJsonParam, ImportMnemonicParam, ImportPrivateKeyParam,
    ImportPrivateKeyResult, KeystoreResult, MnemonicToPublicKeyParam, MnemonicToPublicKeyResult,
    ScanKeystoresResult, SignAuthenticationMessageParam, SignAuthenticationMessageResult,
    SignHashesParam, SignHashesResult, WalletKeyParam,
};
use crate::api::{EthBatchPersonalSignParam, EthBatchPersonalSignResult};
use crate::api::{InitTokenCoreXParam, SignParam};
use crate::error_handling::Result;
use crate::filemanager::{
    cache_keystore, clean_keystore, flush_keystore, KEYSTORE_BASE_DIR, LEGACY_WALLET_FILE_DIR,
    WALLET_FILE_DIR, WALLET_V1_DIR, WALLET_V2_DIR,
};
use crate::filemanager::{delete_keystore_file, KEYSTORE_MAP};

use crate::IS_DEBUG;

use base58::FromBase58;
use tcx_keystore::tcx_ensure;

use tcx_constants::coin_info::coin_info_from_param;
use tcx_constants::{CoinInfo, CurveType};
use tcx_crypto::aes::cbc::encrypt_pkcs7;
use tcx_crypto::KDF_ROUNDS;
use tcx_eth::signer::batch_personal_sign;
use tcx_keystore::{MessageSigner, TransactionSigner};

use tcx_primitive::Ss58Codec;
use tcx_substrate::{decode_substrate_keystore, encode_substrate_keystore, SubstrateKeystore};

use tcx_migration::migration::LegacyKeystore;
use tcx_primitive::TypedDeterministicPublicKey;
use tcx_tezos::{encode_tezos_private_key, parse_tezos_private_key};

use crate::macros::{impl_to_key, use_chains};
use crate::migration::{
    read_all_identity_wallet_ids, remove_all_identity_wallets, remove_old_keystore_by_id,
};
use crate::reset_password::assert_seed_equals;

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

pub fn encode_message(msg: impl Message) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;
    Ok(buf.to_vec())
}

fn derive_account(keystore: &mut Keystore, derivation: &Derivation) -> Result<Account> {
    let mut coin_info = coin_info_from_param(
        &derivation.chain_type,
        &derivation.network,
        &derivation.seg_wit,
        &derivation.curve,
    )?;
    coin_info.derivation_path = derivation.path.to_owned();

    derive_account_internal(&coin_info, keystore)
}

pub fn encrypt_xpub(xpub: &str) -> Result<String> {
    let key = tcx_crypto::XPUB_COMMON_KEY_128.read();
    let iv = tcx_crypto::XPUB_COMMON_IV.read();
    let key_bytes = Vec::from_hex(&*key)?;
    let iv_bytes = Vec::from_hex(&*iv)?;
    let encrypted = encrypt_pkcs7(xpub.as_bytes(), &key_bytes, &iv_bytes)?;
    Ok(base64::encode(encrypted))
}

fn key_data_from_any_format_pk(pk: &str) -> Result<Vec<u8>> {
    let decoded = Vec::from_hex_auto(pk);
    if let Ok(bytes) = decoded {
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

pub(crate) fn fingerprint_from_any_format_pk(pk: &str) -> Result<String> {
    let key_data = if pk.starts_with("edsk") {
        parse_tezos_private_key(pk)?
    } else {
        key_data_from_any_format_pk(pk)?
    };
    fingerprint_from_private_key(&key_data)
}

fn import_private_key_internal(
    param: &ImportPrivateKeyParam,
    source: Option<Source>,
    original: Option<String>,
) -> Result<ImportPrivateKeyResult> {
    let overwrite_id = param.overwrite_id.to_string();
    let mut founded_id: Option<String> = None;
    {
        let fingerprint = fingerprint_from_any_format_pk(&param.private_key)?;
        let map = KEYSTORE_MAP.read();
        if let Some(founded) = map
            .values()
            .find(|keystore| keystore.fingerprint() == fingerprint)
        {
            founded_id = Some(founded.id());
        }
    }

    if founded_id.is_some() && Some(overwrite_id.to_string()) != founded_id {
        return Ok(crate::api::ImportPrivateKeyResult {
            is_existed: true,
            existed_id: founded_id.unwrap().to_string(),
            ..Default::default()
        });
    }

    if !overwrite_id.is_empty() {
        assert_seed_equals(&overwrite_id, &param.private_key, false)?;
        founded_id = Some(overwrite_id);
    }

    let decoded_ret = decode_private_key(&param.private_key)?;
    if !decoded_ret.network.is_empty() {
        let expected_network = if param.network.is_empty() {
            "MAINNET"
        } else {
            param.network.as_str()
        };
        if decoded_ret.network != expected_network {
            return Err(anyhow!("{}", "private_key_network_mismatch"));
        }
    }

    let private_key = decoded_ret.bytes.to_hex();
    let meta_source = if let Some(source) = source {
        source
    } else {
        decoded_ret.source
    };

    let original = if let Some(original) = original {
        original
    } else {
        param.private_key.to_string()
    };

    let meta = Metadata {
        name: param.name.to_string(),
        password_hint: Some(param.password_hint.to_string()),
        source: meta_source,
        identified_chain_types: Some(decoded_ret.chain_types.clone()),
        ..Metadata::default()
    };
    let pk_store = PrivateKeystore::from_private_key(
        &private_key,
        &param.password,
        decoded_ret.curve,
        meta,
        Some(original),
    )?;

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
        created_at: meta.timestamp,
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
        identified_chain_types: decoded_ret.chain_types.to_owned(),
        identified_network: decoded_ret.network.to_string(),
        identified_curve: decoded_ret.curve.as_str().to_string(),
        source_fingerprint: keystore.fingerprint().to_string(),
        ..Default::default()
    };
    cache_keystore(keystore);
    Ok(wallet)
}

pub(crate) struct DecodedPrivateKey {
    pub bytes: Vec<u8>,
    network: String,
    curve: CurveType,
    chain_types: Vec<String>,
    source: Source,
}

pub(crate) fn decode_private_key(private_key: &str) -> Result<DecodedPrivateKey> {
    let private_key_bytes: Vec<u8>;
    let mut network = "".to_string();
    let mut chain_types: Vec<String> = vec![];
    let mut curve: CurveType = CurveType::SECP256k1;
    let mut source: Source = Source::Private;
    if private_key.starts_with("edsk") {
        private_key_bytes = parse_tezos_private_key(private_key)?;
        chain_types.push("TEZOS".to_string());
        curve = CurveType::ED25519;
    } else {
        let decoded = Vec::from_hex_auto(private_key);
        if let Ok(decoded_data) = decoded {
            if decoded_data.len() == 32 {
                private_key_bytes = decoded_data;
                chain_types = vec![
                    "BITCOIN".to_string(),
                    "ETHEREUM".to_string(),
                    "BITCOINCASH".to_string(),
                    "LITECOIN".to_string(),
                    "EOS".to_string(),
                    "TRON".to_string(),
                    "FILECOIN".to_string(),
                ];
                curve = CurveType::SECP256k1;
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
                .map_err(|_| anyhow!("invalid_wif"))?
                .len();
            let (k1_pk, ver) = Secp256k1PrivateKey::from_ss58check_with_version(private_key)?;
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
                _ => return Err(anyhow!("unknow ver header when parse wif, ver: {}", ver[0])),
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
    let ks: LegacyKeystore = serde_json::from_str(keystore)?;
    ks.validate_v3(password)?;
    let key = tcx_crypto::Key::Password(password.to_string());
    let unlocker = ks.crypto.use_key(&key)?;
    let private_key = unlocker.plaintext()?;
    Ok((private_key, "Imported ETH".to_string()))
}

fn key_info_from_substrate_keystore(keystore: &str, password: &str) -> Result<(Vec<u8>, String)> {
    let ks: SubstrateKeystore = serde_json::from_str(keystore)?;
    ks.validate()?;
    let pk = decode_substrate_keystore(&ks, password)?;
    Ok((pk, ks.meta.name))
}

fn curve_to_chain_type(curve: &CurveType) -> Vec<String> {
    match curve {
        CurveType::SECP256k1 => vec![
            "BITCOIN".to_string(),
            "BITCOINCASH".to_string(),
            "LITECOIN".to_string(),
            "FILECOIN".to_string(),
            "EOS".to_string(),
            "TRON".to_string(),
            "COSMOS".to_string(),
        ],
        CurveType::ED25519 => vec!["TEZOS".to_string()],
        CurveType::SR25519 => vec!["KUSAMA".to_string(), "POLKADOT".to_string()],
        CurveType::BLS => vec!["FILECOIN".to_string()],
        _ => vec![],
    }
}

pub fn init_token_core_x(data: &[u8]) -> Result<()> {
    let InitTokenCoreXParam {
        file_dir,
        xpub_common_key,
        xpub_common_iv,
        is_debug,
    } = InitTokenCoreXParam::decode(data).unwrap();
    *KEYSTORE_BASE_DIR.write() = file_dir.to_string();

    let v2_dir = format!("{}/{}", file_dir, WALLET_V2_DIR);
    fs::create_dir_all(&v2_dir)?;
    *WALLET_FILE_DIR.write() = v2_dir.to_string();
    *LEGACY_WALLET_FILE_DIR.write() = format!("{}/{}", file_dir, WALLET_V1_DIR);

    *XPUB_COMMON_KEY_128.write() = xpub_common_key;
    *XPUB_COMMON_IV.write() = xpub_common_iv;

    if is_debug {
        *IS_DEBUG.write() = is_debug;
        if is_debug {
            *KDF_ROUNDS.write() = 1;
        }
    }
    scan_keystores()?;

    Ok(())
}

pub fn scan_keystores() -> Result<ScanKeystoresResult> {
    clean_keystore();
    let file_dir = WALLET_FILE_DIR.read();
    let p = Path::new(file_dir.as_str());
    let walk_dir = std::fs::read_dir(p).expect("read dir");

    let mut hd_keystores: Vec<KeystoreResult> = Vec::new();
    let mut private_key_keystores: Vec<ImportPrivateKeyResult> = Vec::new();

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

        if version == HdKeystore::VERSION || version == PrivateKeystore::VERSION {
            let keystore = Keystore::from_json(&contents)?;

            if version == HdKeystore::VERSION {
                let keystore_result = KeystoreResult {
                    id: keystore.id(),
                    name: keystore.meta().name.to_string(),
                    identifier: keystore.identity().identifier.to_string(),
                    ipfs_id: keystore.identity().ipfs_id.to_string(),
                    source: keystore.meta().source.to_string(),
                    created_at: keystore.meta().timestamp,
                    source_fingerprint: keystore.fingerprint().to_string(),
                    ..Default::default()
                };
                hd_keystores.push(keystore_result);
            } else {
                let curve = keystore
                    .get_curve()
                    .expect("pk keystore must contains curve");
                let kestore_result = ImportPrivateKeyResult {
                    id: keystore.id(),
                    name: keystore.meta().name.to_string(),
                    identifier: keystore.identity().identifier.to_string(),
                    ipfs_id: keystore.identity().ipfs_id.to_string(),
                    source: keystore.meta().source.to_string(),
                    created_at: keystore.meta().timestamp,
                    source_fingerprint: keystore.fingerprint().to_string(),
                    identified_chain_types: curve_to_chain_type(&curve),
                    identified_network: keystore.meta().network.to_string(),
                    identified_curve: curve.as_str().to_string(),
                    ..Default::default()
                };
                private_key_keystores.push(kestore_result);
            }
            cache_keystore(keystore);
        }
    }

    Ok(ScanKeystoresResult {
        hd_keystores,
        private_key_keystores,
    })
}

pub fn create_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: CreateKeystoreParam =
        CreateKeystoreParam::decode(data).expect("create_keystore param");

    let meta = Metadata {
        name: param.name,
        password_hint: Some(param.password_hint),
        source: Source::NewMnemonic,
        network: IdentityNetwork::from_str(&param.network)?,
        ..Metadata::default()
    };

    let ks = HdKeystore::new(&param.password, meta);

    let keystore = Keystore::Hd(ks);
    flush_keystore(&keystore)?;

    let identity = keystore.identity();

    let meta = keystore.meta();
    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: Source::NewMnemonic.to_string(),
        created_at: meta.timestamp,
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
        source_fingerprint: keystore.fingerprint().to_string(),
        ..Default::default()
    };

    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

pub fn import_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
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

    if founded_id.is_some() && Some(param.overwrite_id.to_string()) != founded_id {
        let result = KeystoreResult {
            is_existed: true,
            existed_id: founded_id.unwrap().to_string(),
            ..Default::default()
        };
        let ret = encode_message(result)?;
        return Ok(ret);
    }

    if !param.overwrite_id.is_empty() {
        assert_seed_equals(param.overwrite_id.as_str(), &param.mnemonic, true)?;
        founded_id = Some(param.overwrite_id);
    }

    let meta = Metadata {
        name: param.name,
        password_hint: Some(param.password_hint),
        source: Source::Mnemonic,
        ..Metadata::default()
    };

    let ks = HdKeystore::from_mnemonic(&param.mnemonic, &param.password, meta)?;

    let mut keystore = Keystore::Hd(ks);

    if let Some(id) = founded_id {
        keystore.set_id(&id);
    }

    flush_keystore(&keystore)?;

    let meta = keystore.meta();

    let identity = keystore.identity();

    let wallet = KeystoreResult {
        id: keystore.id(),
        name: meta.name.to_owned(),
        source: Source::Mnemonic.to_string(),
        created_at: meta.timestamp,
        identifier: identity.identifier.to_string(),
        ipfs_id: identity.ipfs_id.to_string(),
        source_fingerprint: keystore.fingerprint().to_string(),
        ..Default::default()
    };
    let ret = encode_message(wallet)?;
    cache_keystore(keystore);
    Ok(ret)
}

impl_to_key!(crate::api::derive_accounts_param::Key);
pub fn derive_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveAccountsParam =
        DeriveAccountsParam::decode(data).expect("derive_accounts param");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    let mut account_responses: Vec<AccountResponse> = vec![];

    for derivation in param.derivations {
        let account = derive_account(guard.keystore_mut(), &derivation)?;
        let mut coin_info = coin_info_from_param(
            &derivation.chain_type,
            &derivation.network,
            &derivation.seg_wit,
            &derivation.curve,
        )?;
        if !derivation.path.is_empty() {
            coin_info.derivation_path = derivation.path;
        }

        let enc_xpub = if account.ext_pub_key.is_empty() {
            Ok("".to_string())
        } else {
            encrypt_xpub(&account.ext_pub_key.to_string())
        }?;

        let account_rsp = AccountResponse {
            chain_type: derivation.chain_type.to_owned(),
            address: account.address.to_owned(),
            path: account.derivation_path.to_owned(),
            curve: account.curve.as_str().to_string(),
            public_key: encode_public_key_internal(&account.public_key, &coin_info)?,
            extended_public_key: account.ext_pub_key.to_string(),
            encrypted_extended_public_key: enc_xpub,
            seg_wit: derivation.seg_wit.to_string(),
        };
        account_responses.push(account_rsp);
    }

    let accounts_rsp = DeriveAccountsResult {
        accounts: account_responses,
    };
    encode_message(accounts_rsp)
}

impl_to_key!(crate::api::export_mnemonic_param::Key);

pub(crate) fn export_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportMnemonicParam =
        ExportMnemonicParam::decode(data).expect("export_mnemonic param");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    tcx_ensure!(
        guard.keystore().derivable(),
        anyhow!("{}", "private_keystore_cannot_export_mnemonic")
    );

    let export_result = ExportMnemonicResult {
        id: guard.keystore().id(),
        mnemonic: guard.keystore().export()?,
    };

    encode_message(export_result)
}

pub fn import_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ImportPrivateKeyParam =
        ImportPrivateKeyParam::decode(data).expect("import_private_key param");

    let rsp = import_private_key_internal(&param, None, None)?;

    let ret = encode_message(rsp)?;
    Ok(ret)
}

impl_to_key!(crate::api::export_private_key_param::Key);
pub(crate) fn export_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportPrivateKeyParam =
        ExportPrivateKeyParam::decode(data).expect("export_private_key param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    let curve = CurveType::from_str(&param.curve);
    let private_key_bytes = guard
        .keystore_mut()
        .get_private_key(curve, &param.path)?
        .to_bytes();

    let value = if ["POLKADOT", "KUSAMA"].contains(&param.chain_type.as_str()) {
        Ok(private_key_bytes.to_0x_hex())
    } else if ["TRON", "ETHEREUM"].contains(&param.chain_type.as_str()) {
        Ok(private_key_bytes.to_hex())
    } else if "FILECOIN".contains(param.chain_type.as_str()) {
        Ok(KeyInfo::from_private_key(curve, &private_key_bytes)?
            .to_json()?
            .to_hex())
    } else if "TEZOS".contains(param.chain_type.as_str()) {
        Ok(encode_tezos_private_key(&private_key_bytes.to_hex())?)
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
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.key.clone().unwrap().into()) {
        let rsp = GeneralResult {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(anyhow!("{}", "password_incorrect"))
    }
}

impl_to_key!(crate::api::wallet_key_param::Key);
pub(crate) fn delete_keystore(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("delete_keystore param");
    let mut map = KEYSTORE_MAP.write();
    let keystore: &Keystore = match map.get(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    if keystore.verify_password(&param.key.clone().unwrap().into()) {
        delete_keystore_file(&param.id)?;
        map.remove(&param.id);

        // Used to delete all duplicated mnemonic keystore
        if let Some(file_ids) = remove_old_keystore_by_id(&param.id.clone()) {
            for file_id in file_ids {
                map.remove(&file_id);
            }
        }

        // Used to delete all identity keystore if is deleting identity wallet
        if let Some(all_identity_wallets) = read_all_identity_wallet_ids() {
            if all_identity_wallets.wallet_ids.contains(&param.id) {
                if let Some(file_ids) = remove_all_identity_wallets() {
                    for file_id in file_ids {
                        map.remove(&file_id);
                    }
                }
            }
        }

        let rsp = GeneralResult {
            is_success: true,
            error: "".to_owned(),
        };
        encode_message(rsp)
    } else {
        Err(anyhow!("{}", "password_incorrect"))
    }
}

pub(crate) fn exists_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsPrivateKeyParam =
        ExistsPrivateKeyParam::decode(data).expect("exists_private_key param");
    let fingerprint = fingerprint_from_any_format_pk(&param.private_key)?;

    exists_fingerprint(&fingerprint)
}

pub(crate) fn exists_mnemonic(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExistsMnemonicParam =
        ExistsMnemonicParam::decode(data).expect("exists_mnemonic param");

    let key_hash = fingerprint_from_mnemonic(&param.mnemonic)?;

    exists_fingerprint(&key_hash)
}

impl_to_key!(crate::api::sign_param::Key);

pub(crate) fn sign_tx(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignParam = SignParam::decode(data).expect("sign_tx param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    sign_transaction_internal(&param, guard.keystore_mut())
}

impl_to_key!(crate::api::sign_hashes_param::Key);
pub(crate) fn sign_hashes(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignHashesParam = SignHashesParam::decode(data).expect("sign_hashes param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

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

impl_to_key!(crate::api::get_public_keys_param::Key);
pub(crate) fn get_public_keys(data: &[u8]) -> Result<Vec<u8>> {
    let param: GetPublicKeysParam =
        GetPublicKeysParam::decode(data).expect("get_public_keys param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    let public_keys: Vec<TypedPublicKey> = param
        .derivations
        .iter()
        .map(|derivation| {
            guard
                .keystore_mut()
                .get_public_key(CurveType::from_str(&derivation.curve), &derivation.path)
                .expect("PublicKeyProcessed")
        })
        .collect();

    let mut public_key_strs: Vec<String> = vec![];
    for idx in 0..param.derivations.len() {
        let pub_key = &public_keys[idx];
        let derivation = &param.derivations[idx];
        let coin_info = CoinInfo {
            coin: derivation.chain_type.to_string(),
            derivation_path: derivation.path.to_string(),
            curve: CurveType::from_str(&derivation.curve),
            ..Default::default()
        };

        let public_key_str_ret = encode_public_key_internal(&pub_key, &coin_info);

        let pub_key_str = public_key_str_ret?;
        public_key_strs.push(pub_key_str);
    }

    encode_message(GetPublicKeysResult {
        public_keys: public_key_strs,
    })
}

impl_to_key!(crate::api::get_extended_public_keys_param::Key);
pub(crate) fn get_extended_public_keys(data: &[u8]) -> Result<Vec<u8>> {
    let param: GetExtendedPublicKeysParam =
        GetExtendedPublicKeysParam::decode(data).expect("get_extended_public_keys param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

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
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    sign_message_internal(&param, guard.keystore_mut())
}

pub fn get_derived_key(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("get_derived_key param");
    let mut map: parking_lot::lock_api::RwLockWriteGuard<
        '_,
        parking_lot::RawRwLock,
        std::collections::HashMap<String, Keystore>,
    > = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let Some(api::wallet_key_param::Key::Password(password)) = param.key else {
        return Err(anyhow!("{}", "get_derived_key need password"));
    };
    let dk = keystore.get_derived_key(&password)?;

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
        // network is required when import wif
        let pk_import_param = ImportPrivateKeyParam {
            private_key: sec_key_bytes.to_hex(),
            password: param.password.to_string(),
            name,
            password_hint: "".to_string(),
            network: "".to_string(),
            overwrite_id: "".to_string(),
        };
        let mut ret = import_private_key_internal(
            &pk_import_param,
            Some(Source::KeystoreV3),
            Some(param.json.to_string()),
        )?;
        ret.identified_chain_types = vec!["ETHEREUM".to_string()];
        ret.identified_curve = CurveType::SECP256k1.as_str().to_string();
        ret.identified_network = "".to_string();
        encode_message(ret)
    } else if let Ok(parse_substrate_result) =
        key_info_from_substrate_keystore(&param.json, &param.password)
    {
        let (sec_key_bytes, name) = parse_substrate_result;
        let pk_import_param = ImportPrivateKeyParam {
            private_key: sec_key_bytes.to_hex(),
            password: param.password.to_string(),
            name,
            password_hint: "".to_string(),
            network: "".to_string(),
            overwrite_id: "".to_string(),
        };
        let mut ret = import_private_key_internal(
            &pk_import_param,
            Some(Source::SubstrateKeystore),
            Some(param.json.to_string()),
        )?;
        ret.identified_chain_types = vec!["KUSAMA".to_string(), "POLKADOT".to_string()];
        ret.identified_curve = CurveType::SR25519.as_str().to_string();
        ret.identified_network = "".to_string();
        return encode_message(ret);
    } else {
        return Err(anyhow!("unsupport_chain"));
    }
}

pub(crate) fn export_json(data: &[u8]) -> Result<Vec<u8>> {
    let param: ExportJsonParam = ExportJsonParam::decode(data).expect("export_json param");
    let meta: Metadata;
    {
        let map = KEYSTORE_MAP.read();

        let keystore: &Keystore = match map.get(&param.id) {
            Some(keystore) => Ok(keystore),
            _ => Err(anyhow!("{}", "wallet_not_found")),
        }?;

        // !!! Warning !!! HDKeystore only can export raw sr25519 key,
        // but polkadotjs fixtures needs a Ed25519 expanded secret key.
        // they will generate difference account address
        if ["POLKADOT".to_string(), "KUSAMA".to_string()].contains(&param.chain_type)
            && keystore.derivable()
        {
            return Err(anyhow!("{}", "only_support_sr25519_keystore"));
        }
        meta = keystore.meta();
    }

    let curve = if ["POLKADOT".to_string(), "KUSAMA".to_string()].contains(&param.chain_type) {
        CurveType::SR25519.as_str().to_string()
    } else {
        CurveType::SECP256k1.as_str().to_string()
    };

    let export_pivate_key_param = ExportPrivateKeyParam {
        id: param.id.to_string(),
        key: Some(export_private_key_param::Key::Password(
            param.password.to_owned(),
        )),
        chain_type: param.chain_type.to_string(),
        network: "".to_string(),
        curve,
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
        _ => return Err(anyhow!("unsupported_chain")),
    };

    let ret = ExportJsonResult {
        id: param.id,
        json: json_str,
    };
    encode_message(ret)
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
        return Err(anyhow!("decrypt_json_error"));
    };

    let exists_param = ExistsPrivateKeyParam {
        private_key: sec_key_hex,
    };
    let exists_param_bytes = encode_message(exists_param)?;
    exists_private_key(&exists_param_bytes)
}

pub(crate) fn backup(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).expect("backup param");

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let original = keystore.backup(&param.key.clone().unwrap().into())?;
    let fingerprint = match keystore.meta().source {
        Source::Mnemonic | Source::NewMnemonic => Some(fingerprint_from_mnemonic(&original)?),
        Source::Private | Source::Wif => Some(fingerprint_from_any_format_pk(&original)?),
        Source::KeystoreV3 | Source::SubstrateKeystore => None,
    };
    if fingerprint.is_none()
        || fingerprint
            .unwrap()
            .eq_ignore_ascii_case(keystore.fingerprint())
    {
        encode_message(BackupResult { original })
    } else {
        Err(anyhow!("fingerprint_not_match"))
    }
}

pub(crate) fn unlock_then_crash(data: &[u8]) -> Result<Vec<u8>> {
    let param: WalletKeyParam = WalletKeyParam::decode(data).unwrap();
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let _guard = keystore.unlock(&param.key.unwrap().into());
    panic!("test_unlock_then_crash");
}

pub(crate) fn encrypt_data_to_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let param = EncryptDataToIpfsParam::decode(data).expect("EncryptDataToIpfsParam");

    let map = KEYSTORE_MAP.read();
    let cipher_text = if let Some(identity_ks) = map
        .values()
        .find(|ks| ks.identity().identifier == param.identifier)
    {
        identity_ks.identity().encrypt_ipfs(&param.content)?
    } else {
        let legacy_identify_path = &format!("{}/identity.json", LEGACY_WALLET_FILE_DIR.read());
        let legacy_ipfs_info = legacy_ipfs::read_legacy_ipfs_info(&legacy_identify_path)?;
        ensure!(
            legacy_ipfs_info.identifier == param.identifier,
            "wallet_not_found"
        );
        identity::encrypt_ipfs_with_enc_key(&legacy_ipfs_info.enc_key, &param.content)?
    };

    let output = EncryptDataToIpfsResult {
        identifier: param.identifier.to_string(),
        encrypted: cipher_text,
    };

    encode_message(output)
}

pub(crate) fn decrypt_data_from_ipfs(data: &[u8]) -> Result<Vec<u8>> {
    let param = DecryptDataFromIpfsParam::decode(data).expect("DecryptDataFromIpfsParam");

    let map = KEYSTORE_MAP.read();
    let content = if let Some(identity_ks) = map
        .values()
        .find(|ks| ks.identity().identifier == param.identifier)
    {
        identity_ks.identity().decrypt_ipfs(&param.encrypted)?
    } else {
        let legacy_identify_path = &format!("{}/identity.json", LEGACY_WALLET_FILE_DIR.read());
        let legacy_ipfs_data = legacy_ipfs::read_legacy_ipfs_info(&legacy_identify_path)?;
        identity::decrypt_ipfs_with_enc_key(
            &param.encrypted,
            &legacy_ipfs_data.ipfs_id,
            &legacy_ipfs_data.enc_key,
        )?
    };

    let output = DecryptDataFromIpfsResult {
        identifier: param.identifier.to_string(),
        content,
    };

    encode_message(output)
}

impl_to_key!(crate::api::sign_authentication_message_param::Key);
pub(crate) fn sign_authentication_message(data: &[u8]) -> Result<Vec<u8>> {
    let param =
        SignAuthenticationMessageParam::decode(data).expect("SignAuthenticationMessageParam");

    let map = KEYSTORE_MAP.read();
    let Some(identity_ks) = map.values().find(|ks| ks.identity().identifier == param.identifier) else {
        return Err(anyhow::anyhow!("identity_not_found"));
    };

    let unlocker = identity_ks
        .store()
        .crypto
        .use_key(&param.key.clone().unwrap().into())?;

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

pub fn derive_sub_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveSubAccountsParam =
        DeriveSubAccountsParam::decode(data).expect("DeriveSubAccountsParam");

    let curve = CurveType::from_str(&param.curve);
    let xpub = TypedDeterministicPublicKey::from_ss58check(curve, &param.extended_public_key)?;

    let account_ret: Vec<Result<AccountResponse>> = param
        .relative_paths
        .iter()
        .map(|relative_path| {
            let mut coin_info = coin_info_from_param(
                &param.chain_type,
                &param.network,
                &param.seg_wit,
                &param.curve,
            )?;
            coin_info.derivation_path = relative_path.to_string();
            let acc: Account = derive_sub_account(&xpub, &coin_info)?;

            let enc_xpub = encrypt_xpub(&param.extended_public_key.to_string())?;

            let acc_rsp = AccountResponse {
                chain_type: param.chain_type.to_string(),
                address: acc.address.to_string(),
                path: relative_path.to_string(),
                extended_public_key: param.extended_public_key.to_string(),
                encrypted_extended_public_key: enc_xpub,
                public_key: encode_public_key_internal(&acc.public_key, &coin_info)?,
                curve: param.curve.to_string(),
                seg_wit: param.seg_wit.to_string(),
            };
            Ok(acc_rsp)
        })
        .collect();

    let accounts: Vec<AccountResponse> = account_ret
        .into_iter()
        .collect::<Result<Vec<AccountResponse>>>()?;

    encode_message(DeriveSubAccountsResult { accounts })
}

pub fn mnemonic_to_public(data: &[u8]) -> Result<Vec<u8>> {
    let param = MnemonicToPublicKeyParam::decode(data)?;
    let public_key = tcx_primitive::mnemonic_to_public(&param.mnemonic, &param.path, &param.curve)?;
    let coin_info = CoinInfo {
        derivation_path: param.path,
        curve: CurveType::from_str(&param.curve),
        coin: param.encoding,
        ..Default::default()
    };
    let public_key_str = encode_public_key_internal(&public_key, &coin_info)?;
    encode_message(MnemonicToPublicKeyResult {
        public_key: public_key_str,
    })
}

pub(crate) fn sign_bls_to_execution_change(data: &[u8]) -> Result<Vec<u8>> {
    let param: SignBlsToExecutionChangeParam = SignBlsToExecutionChangeParam::decode(data)?;
    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;
    let mut guard = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;
    let result: SignBlsToExecutionChangeResult =
        param.sign_bls_to_execution_change(guard.keystore_mut())?;
    encode_message(result)
}

impl_to_key!(crate::api::eth_batch_personal_sign_param::Key);
pub(crate) fn eth_batch_personal_sign(data: &[u8]) -> Result<Vec<u8>> {
    let param: EthBatchPersonalSignParam = EthBatchPersonalSignParam::decode(data)?;

    let mut map = KEYSTORE_MAP.write();
    let keystore: &mut Keystore = match map.get_mut(&param.id) {
        Some(keystore) => Ok(keystore),
        _ => Err(anyhow!("{}", "wallet_not_found")),
    }?;

    let mut keystore = KeystoreGuard::unlock(keystore, param.key.clone().unwrap().into())?;

    let signatures = batch_personal_sign(keystore.keystore_mut(), param.data, &param.path)?;

    encode_message(EthBatchPersonalSignResult { signatures })
}

pub(crate) fn private_key_to_account_dynamic(
    coin_info: &CoinInfo,
    sec_key: &[u8],
) -> Result<Account> {
    private_key_to_account_internal(coin_info, sec_key)
}

#[cfg(test)]
mod tests {
    use tcx_constants::CurveType;
    use tcx_keystore::Source;

    use crate::{api::ImportPrivateKeyResult, filemanager::WALLET_FILE_DIR};

    use super::{decode_private_key, scan_keystores};
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
                "LITECOIN".to_string(),
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
        assert_eq!(decoded.curve, CurveType::ED25519);
        assert_eq!(decoded.network, "".to_string());
        assert_eq!(decoded.source, Source::Private);

        let private_key = "0x43fe394358d14f2e096f4efe80894b4e51a3fdcb73c06b77e937b80deb8c746b";
        let decoded = decode_private_key(&private_key).unwrap();
        assert_eq!(
            decoded.chain_types,
            vec![
                "BITCOIN".to_string(),
                "ETHEREUM".to_string(),
                "BITCOINCASH".to_string(),
                "LITECOIN".to_string(),
                "EOS".to_string(),
                "TRON".to_string(),
                "FILECOIN".to_string(),
            ]
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

    #[test]
    fn test_scan_keystores() {
        *WALLET_FILE_DIR.write() = "../test-data/scan-keystores-fixtures/".to_string();
        let result = scan_keystores().unwrap();
        assert_eq!(result.hd_keystores.len(), 1);
        let hd = result.hd_keystores.first().unwrap();
        assert_eq!(hd.id, "1055741c-2904-4973-b7ee-4b69bfd8bcc6");
        assert_eq!(hd.identifier, "im14x5UYkoqtYbJFTLam7c9Ft4BQiFvJbieKWfK");
        assert_eq!(hd.ipfs_id, "Qme1RuM33X8SmVjisWS3sP4irqNZv6vuqL3L3T6poZ6c2b");
        assert_eq!(
            hd.source_fingerprint,
            "0x572d4a6f166f1f25e7e1c7da85cf158568de63d2"
        );
        assert_eq!(hd.created_at, 1705040852);
        assert_eq!(hd.source, "MNEMONIC");
        assert_eq!(hd.name, "test-wallet");
        assert_eq!(result.private_key_keystores.len(), 4);

        let founded_pk_stores: Vec<&ImportPrivateKeyResult> = result
            .private_key_keystores
            .iter()
            .filter(|x| x.id == "7e1c2c55-5b7f-4a5a-8061-c42b594ceb2f")
            .collect();
        let pk = founded_pk_stores.first().unwrap();
        assert_eq!(pk.identifier, "im14x5LYRt5YsM5iTr2xd6dQ75euijaoDs3nRB2");
        assert_eq!(pk.ipfs_id, "QmSpWyzy5gkYyJiagFHzfkJwqzDdcjCA3qeu8T3JFd54vZ");
        assert_eq!(
            pk.source_fingerprint,
            "0xc7b60806a2af1e89f107b9410da3ab8a825fe5a2"
        );
        assert_eq!(pk.created_at, 1705040730);
        assert_eq!(pk.source, "PRIVATE");
        assert_eq!(pk.name, "test_filecoin_import_private_key");
        assert_eq!(pk.identified_curve, "bls12-381");

        let founded_pk_stores: Vec<&ImportPrivateKeyResult> = result
            .private_key_keystores
            .iter()
            .filter(|x| x.id == "1233134b-8377-4fb0-b06f-56062e858708")
            .collect();
        let pk = founded_pk_stores.first().unwrap();
        assert_eq!(pk.identifier, "im14x5FoX7EWwJ1KkNyfSzjafR6JZ6wqUUVr3mR");
        assert_eq!(pk.ipfs_id, "QmQmj2fza2Ep3hxZZRoeco3ZKccoP1vvGJ3ddjDrDMV9UF");
        assert_eq!(
            pk.source_fingerprint,
            "0xa27b5222f4f53dee8c446a380cf40370a48992c3"
        );
        assert_eq!(pk.created_at, 1705041327);
        assert_eq!(pk.source, "SUBSTRATE_KEYSTORE");
        assert_eq!(pk.name, "test account");
        assert_eq!(pk.identified_curve, "sr25519");

        let founded_pk_stores: Vec<&ImportPrivateKeyResult> = result
            .private_key_keystores
            .iter()
            .filter(|x| x.id == "beb68589-0f0f-41e2-94d9-d78f10a72dec")
            .collect();
        let pk = founded_pk_stores.first().unwrap();
        assert_eq!(pk.identifier, "im14x5UPbCXmU2HMQ8jfeKcCDrQYhDppRYaa5C6");
        assert_eq!(pk.ipfs_id, "QmczBPUeohPPaE8UnPiESyynPwffBqrn4RqrU6nPJw95VT");
        assert_eq!(
            pk.source_fingerprint,
            "0xe6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
        assert_eq!(pk.created_at, 1705040607);
        assert_eq!(pk.source, "PRIVATE");
        assert_eq!(pk.name, "test_filecoin_import_private_key");
        assert_eq!(pk.identified_curve, "secp256k1");

        let founded_pk_stores: Vec<&ImportPrivateKeyResult> = result
            .private_key_keystores
            .iter()
            .filter(|x| x.id == "beb68589-0f0f-41e2-94d9-d78f10a72dec")
            .collect();
        let pk = founded_pk_stores.first().unwrap();
        assert_eq!(pk.identifier, "im14x5UPbCXmU2HMQ8jfeKcCDrQYhDppRYaa5C6");
        assert_eq!(pk.ipfs_id, "QmczBPUeohPPaE8UnPiESyynPwffBqrn4RqrU6nPJw95VT");
        assert_eq!(
            pk.source_fingerprint,
            "0xe6cfaab9a59ba187f0a45db0b169c21bb48f09b3"
        );
        assert_eq!(pk.created_at, 1705040607);
        assert_eq!(pk.source, "PRIVATE");
        assert_eq!(pk.name, "test_filecoin_import_private_key");
        assert_eq!(pk.identified_curve, "secp256k1");

        let founded_pk_stores: Vec<&ImportPrivateKeyResult> = result
            .private_key_keystores
            .iter()
            .filter(|x| x.id == "efcfffb2-9b63-418b-a9d0-ec3600012284")
            .collect();
        let pk = founded_pk_stores.first().unwrap();
        assert_eq!(pk.identifier, "im14x5AU2zU5oRyNdGgNbemdP39ATmu16eVgPFQ");
        assert_eq!(pk.ipfs_id, "Qmb8K5w1fzdTbjTiATvSecNgZYvbMJ6gJB9JPG254aEY8F");
        assert_eq!(
            pk.source_fingerprint,
            "0x6bd7cc4e20a7de71296b81758d29447dfde9a388"
        );
        assert_eq!(pk.created_at, 1705041022);
        assert_eq!(pk.source, "PRIVATE");
        assert_eq!(pk.name, "test_tezos_import_private_key_export");
        assert_eq!(pk.identified_curve, "ed25519");
    }
}
