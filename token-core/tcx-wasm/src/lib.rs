use std::cell::RefCell;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use secp256k1::SecretKey;
use wasm_bindgen::prelude::*;

mod nostr;
mod types;

use tcx_common::{FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_eth::address::EthAddress;
use tcx_eth::transaction::{
    AccessList as ProtoAccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
    SignatureType,
};
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{
    Keystore, MessageSigner, Metadata, SignatureParameters, Source, TransactionSigner,
};
use tcx_primitive::{generate_mnemonic, TypedPublicKey};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use tcx_tron::TronAddress;

use types::*;

thread_local! {
    static CACHED_KEYSTORE_JSON: RefCell<Option<String>> = const { RefCell::new(None) };
    static CACHED_MESSAGE_SECRET_KEY: RefCell<Option<SecretKey>> = const { RefCell::new(None) };
}

const PASSKEY_KEYSTORE_VERSION: u32 = 2;
const PASSKEY_KEYSTORE_CIPHER: &str = "chacha20-poly1305";
const PASSKEY_NONCE_LEN: usize = 12;

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn resolve_keystore_json(explicit: Option<String>) -> Result<String, JsValue> {
    if let Some(json) = explicit {
        return Ok(json);
    }
    CACHED_KEYSTORE_JSON.with(|cache| {
        cache
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("keystore_json not provided and no cached keystore"))
    })
}

fn now_timestamp() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

fn passkey_metadata(network: IdentityNetwork) -> Metadata {
    Metadata {
        name: "Unknown".to_string(),
        password_hint: None,
        timestamp: now_timestamp(),
        source: Source::Mnemonic,
        network,
        identified_chain_types: None,
    }
}

fn parse_prf_key(prf_key_hex: &str) -> Result<[u8; 32], JsValue> {
    let prf_key = Vec::from_hex(prf_key_hex).map_err(to_js_err)?;
    if prf_key.len() != 32 {
        return Err(JsValue::from_str("PRF key must be 32 bytes"));
    }

    prf_key
        .try_into()
        .map_err(|_| JsValue::from_str("PRF key must be 32 bytes"))
}

fn keystore_aad(keystore: &PasskeyKeystore) -> Result<Vec<u8>, JsValue> {
    serde_json::to_vec(&(
        keystore.version,
        keystore.cipher.as_str(),
        keystore.user_id.as_str(),
        keystore.credential_id.as_str(),
        keystore.rp_id.as_str(),
        keystore.created_at,
        keystore.network.as_str(),
        &keystore.identity,
    ))
    .map_err(to_js_err)
}

fn encrypt_mnemonic_v2(
    mnemonic: &str,
    prf_key: &[u8; 32],
    keystore: &PasskeyKeystore,
) -> Result<(String, String), JsValue> {
    let mut nonce = [0u8; PASSKEY_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(to_js_err)?;
    let cipher_nonce = Nonce::from(nonce);
    let encrypted = ChaCha20Poly1305::new(prf_key.into())
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: mnemonic.as_bytes(),
                aad: &keystore_aad(keystore)?,
            },
        )
        .map_err(|_| JsValue::from_str("keystore_encryption_failed"))?;
    Ok((encrypted.to_hex(), nonce.to_hex()))
}

fn decrypt_mnemonic(keystore: &PasskeyKeystore, prf_key_hex: &str) -> Result<String, JsValue> {
    let prf_key = parse_prf_key(prf_key_hex)?;
    let encrypted = Vec::from_hex(&keystore.encrypted_mnemonic).map_err(to_js_err)?;

    let decrypted = if keystore.version == PASSKEY_KEYSTORE_VERSION {
        if keystore.cipher != PASSKEY_KEYSTORE_CIPHER {
            return Err(JsValue::from_str("unsupported_passkey_keystore_cipher"));
        }
        let nonce: [u8; PASSKEY_NONCE_LEN] = Vec::from_hex(&keystore.mnemonic_nonce)
            .map_err(to_js_err)?
            .try_into()
            .map_err(|_| JsValue::from_str("invalid_passkey_keystore_nonce"))?;
        let nonce = Nonce::from(nonce);
        ChaCha20Poly1305::new((&prf_key).into())
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted,
                    aad: &keystore_aad(keystore)?,
                },
            )
            .map_err(|_| JsValue::from_str("keystore_authentication_failed"))?
    } else if keystore.version <= 1
        && (keystore.cipher.is_empty() || keystore.cipher == "aes-128-ctr")
    {
        let iv = Vec::from_hex(&keystore.mnemonic_iv).map_err(to_js_err)?;
        tcx_crypto::aes::ctr::decrypt_nopadding(&encrypted, &prf_key[..16], &iv)
            .map_err(to_js_err)?
    } else {
        return Err(JsValue::from_str("unsupported_passkey_keystore_version"));
    };

    String::from_utf8(decrypted).map_err(to_js_err)
}

fn unlock_validated_keystore(
    mnemonic: &str,
    expected: &PasskeyKeystore,
) -> Result<(Keystore, &'static str), JsValue> {
    let password = "";
    let networks: &[(&str, IdentityNetwork)] = match expected.network.as_str() {
        "MAINNET" => &[("MAINNET", IdentityNetwork::Mainnet)],
        "TESTNET" => &[("TESTNET", IdentityNetwork::Testnet)],
        _ => &[
            ("MAINNET", IdentityNetwork::Mainnet),
            ("TESTNET", IdentityNetwork::Testnet),
        ],
    };

    for (network_name, network) in networks {
        let metadata = passkey_metadata(*network);
        if let Ok(mut keystore) = Keystore::from_mnemonic(mnemonic, password, metadata) {
            if keystore.store().identity.identifier == expected.identity.identifier {
                keystore.unlock_by_password(password).map_err(to_js_err)?;
                return Ok((keystore, network_name));
            }
        }
    }

    Err(JsValue::from_str("passkey_keystore_identity_mismatch"))
}

fn clear_message_key_pair() {
    CACHED_MESSAGE_SECRET_KEY.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

fn get_cached_secret_key() -> Result<SecretKey, JsValue> {
    CACHED_MESSAGE_SECRET_KEY.with(|cache| {
        (*cache.borrow()).ok_or_else(|| {
            JsValue::from_str("message key pair not derived, call deriveMessageKeyPair first")
        })
    })
}

#[wasm_bindgen]
pub fn cache_keystore(keystore_json: &str) {
    clear_message_key_pair();
    CACHED_KEYSTORE_JSON.with(|cache| {
        *cache.borrow_mut() = Some(keystore_json.to_string());
    });
}

#[wasm_bindgen]
pub fn clear_cached_keystore() {
    clear_message_key_pair();
    CACHED_KEYSTORE_JSON.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

#[wasm_bindgen]
pub fn create_keystore(param_json: &str) -> Result<String, JsValue> {
    let param: CreateKeystoreParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let prf_key = parse_prf_key(&param.prf_key)?;

    let mnemonic = match (param.mnemonic, param.entropy) {
        (Some(m), _) => m,
        (None, Some(entropy_hex)) => {
            let entropy = Vec::from_hex(&entropy_hex).map_err(to_js_err)?;
            bip39::Mnemonic::from_entropy(&entropy)
                .map_err(to_js_err)?
                .to_string()
        }
        (None, None) => generate_mnemonic(),
    };

    let (network_name, network) = match param.network.as_deref() {
        Some("TESTNET") => ("TESTNET", IdentityNetwork::Testnet),
        _ => ("MAINNET", IdentityNetwork::Mainnet),
    };
    let meta = passkey_metadata(network);
    let keystore = Keystore::from_mnemonic(&mnemonic, "", meta).map_err(to_js_err)?;
    let identity = keystore.store().identity.clone();

    let mut result = PasskeyKeystore {
        version: PASSKEY_KEYSTORE_VERSION,
        cipher: PASSKEY_KEYSTORE_CIPHER.to_string(),
        user_id: param.user_id,
        credential_id: param.credential_id,
        rp_id: param.rp_id,
        encrypted_mnemonic: String::new(),
        mnemonic_iv: String::new(),
        mnemonic_nonce: String::new(),
        network: network_name.to_string(),
        created_at: now_timestamp(),
        identity,
    };
    let (encrypted_mnemonic, mnemonic_nonce) = encrypt_mnemonic_v2(&mnemonic, &prf_key, &result)?;
    result.encrypted_mnemonic = encrypted_mnemonic;
    result.mnemonic_nonce = mnemonic_nonce;

    serde_json::to_string(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn migrate_keystore(param_json: &str) -> Result<String, JsValue> {
    let param: MigrateKeystoreParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let original_value: serde_json::Value =
        serde_json::from_str(&param.keystore_json).map_err(to_js_err)?;
    let old_keystore: PasskeyKeystore =
        serde_json::from_value(original_value.clone()).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&old_keystore, &param.prf_key)?;
    let (mut validated_keystore, network) = unlock_validated_keystore(&mnemonic, &old_keystore)?;
    validated_keystore.lock();

    if old_keystore.version == PASSKEY_KEYSTORE_VERSION {
        return Ok(param.keystore_json);
    }

    let prf_key = parse_prf_key(&param.prf_key)?;
    let mut migrated = PasskeyKeystore {
        version: PASSKEY_KEYSTORE_VERSION,
        cipher: PASSKEY_KEYSTORE_CIPHER.to_string(),
        user_id: old_keystore.user_id,
        credential_id: old_keystore.credential_id,
        rp_id: old_keystore.rp_id,
        encrypted_mnemonic: String::new(),
        mnemonic_iv: String::new(),
        mnemonic_nonce: String::new(),
        network: network.to_string(),
        created_at: old_keystore.created_at,
        identity: old_keystore.identity,
    };
    let (encrypted_mnemonic, mnemonic_nonce) = encrypt_mnemonic_v2(&mnemonic, &prf_key, &migrated)?;
    migrated.encrypted_mnemonic = encrypted_mnemonic;
    migrated.mnemonic_nonce = mnemonic_nonce;

    let mut migrated_value = serde_json::to_value(migrated).map_err(to_js_err)?;
    if let (Some(original), Some(output)) =
        (original_value.as_object(), migrated_value.as_object_mut())
    {
        for (key, value) in original {
            output.entry(key.clone()).or_insert_with(|| value.clone());
        }
        output.remove("mnemonicIv");
    }

    serde_json::to_string(&migrated_value).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_accounts(param_json: &str) -> Result<String, JsValue> {
    let param: DeriveAccountsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    if param.derivations.is_empty() {
        return Err(JsValue::from_str("derivations must not be empty"));
    }

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, &param.prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;

    let mut results: Vec<AccountResponse> = Vec::with_capacity(param.derivations.len());

    for item in &param.derivations {
        let chain = item.chain.as_deref().unwrap_or("ETHEREUM");
        let coin_name = match chain {
            "TRON" => "TRON",
            _ => "ETHEREUM",
        };

        let coin_info = tcx_constants::CoinInfo {
            chain_id: item.chain_id.clone().unwrap_or_default(),
            coin: coin_name.to_string(),
            derivation_path: item.derivation_path.clone(),
            curve: CurveType::SECP256k1,
            network: item.network.as_deref().unwrap_or("MAINNET").to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };

        let account = match chain {
            "TRON" => keystore
                .derive_coin::<TronAddress>(&coin_info)
                .map_err(to_js_err)?,
            _ => keystore
                .derive_coin::<EthAddress>(&coin_info)
                .map_err(to_js_err)?,
        };

        results.push(AccountResponse {
            address: account.address,
            chain: coin_name.to_string(),
            derivation_path: account.derivation_path,
            ext_pub_key: account.ext_pub_key,
            public_key: encode_public_key(&account.public_key),
        });
    }

    keystore.lock();
    serde_json::to_string(&results).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn export_mnemonic(param_json: &str) -> Result<String, JsValue> {
    let param: ExportMnemonicParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, &param.prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;
    keystore.lock();

    serde_json::to_string(&serde_json::json!({ "mnemonic": mnemonic })).map_err(to_js_err)
}

fn sign_single_tx(
    keystore: &mut Keystore,
    chain: &str,
    derivation_path: Option<String>,
    input: serde_json::Value,
) -> Result<serde_json::Value, JsValue> {
    let default_path = match chain {
        "TRON" => "m/44'/195'/0'/0/0",
        _ => "m/44'/60'/0'/0/0",
    };

    let derivation_path = derivation_path.unwrap_or_else(|| default_path.to_string());

    let sign_params = SignatureParameters {
        curve: CurveType::SECP256k1,
        derivation_path,
        chain_type: chain.to_string(),
        network: "".to_string(),
        seg_wit: "".to_string(),
    };

    match chain {
        "TRON" => {
            let tron_input_json: TronTxInputJson =
                serde_json::from_value(input).map_err(to_js_err)?;
            let tron_input = TronTxInput {
                raw_data: tron_input_json.raw_data,
            };
            let output: TronTxOutput = keystore
                .sign_transaction(&sign_params, &tron_input)
                .map_err(to_js_err)?;
            Ok(serde_json::json!({ "signatures": output.signatures }))
        }
        _ => {
            let eth_input_json: EthTxInputJson =
                serde_json::from_value(input).map_err(to_js_err)?;
            let access_list: Vec<ProtoAccessList> = eth_input_json
                .access_list
                .unwrap_or_default()
                .into_iter()
                .map(|item| ProtoAccessList {
                    address: item.address,
                    storage_keys: item.storage_keys,
                })
                .collect();
            let eth_input = EthTxInput {
                nonce: eth_input_json.nonce,
                gas_price: eth_input_json.gas_price.unwrap_or_default(),
                gas_limit: eth_input_json.gas_limit,
                to: eth_input_json.to,
                value: eth_input_json.value,
                data: eth_input_json.data.unwrap_or_default(),
                chain_id: eth_input_json.chain_id,
                tx_type: eth_input_json.tx_type.unwrap_or_default(),
                max_fee_per_gas: eth_input_json.max_fee_per_gas.unwrap_or_default(),
                max_priority_fee_per_gas: eth_input_json
                    .max_priority_fee_per_gas
                    .unwrap_or_default(),
                access_list,
            };
            let output: EthTxOutput = keystore
                .sign_transaction(&sign_params, &eth_input)
                .map_err(to_js_err)?;
            Ok(serde_json::json!({
                "signature": output.signature,
                "txHash": output.tx_hash,
            }))
        }
    }
}

#[wasm_bindgen]
pub fn sign_tx(param_json: &str) -> Result<String, JsValue> {
    let param: SignTxParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, &param.prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;
    let chain = param.chain.as_deref().unwrap_or("ETHEREUM");
    let json_result = sign_single_tx(&mut keystore, chain, param.derivation_path, param.input)?;

    keystore.lock();
    serde_json::to_string(&json_result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_txs(param_json: &str) -> Result<String, JsValue> {
    let param: SignTxsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    if param.txs.is_empty() {
        return Err(JsValue::from_str("txs must not be empty"));
    }

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, &param.prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;

    let mut results: Vec<serde_json::Value> = Vec::with_capacity(param.txs.len());
    for tx in param.txs {
        let chain = tx.chain.as_deref().unwrap_or("ETHEREUM");
        let result = sign_single_tx(&mut keystore, chain, tx.derivation_path, tx.input)?;
        results.push(result);
    }

    keystore.lock();
    serde_json::to_string(&results).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_message(param_json: &str) -> Result<String, JsValue> {
    let param: SignMessageParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, &param.prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;

    let chain = param.chain.as_deref().unwrap_or("ETHEREUM");
    let default_path = match chain {
        "TRON" => "m/44'/195'/0'/0/0",
        _ => "m/44'/60'/0'/0/0",
    };

    let derivation_path = param
        .derivation_path
        .unwrap_or_else(|| default_path.to_string());

    let sign_params = SignatureParameters {
        curve: CurveType::SECP256k1,
        derivation_path,
        chain_type: chain.to_string(),
        network: "".to_string(),
        seg_wit: "".to_string(),
    };

    let json_result = match chain {
        "TRON" => {
            let input_json: TronSignMessageInputJson =
                serde_json::from_value(param.input).map_err(to_js_err)?;
            let tron_input = TronMessageInput {
                value: input_json.value,
                header: input_json.header.unwrap_or_else(|| "TRON".to_string()),
                version: input_json.version.unwrap_or(1),
            };
            let output: TronMessageOutput = keystore
                .sign_message(&sign_params, &tron_input)
                .map_err(to_js_err)?;
            serde_json::json!({ "signature": output.signature })
        }
        _ => {
            let input_json: EthSignMessageInputJson =
                serde_json::from_value(param.input).map_err(to_js_err)?;
            let signature_type = match input_json
                .signature_type
                .as_deref()
                .unwrap_or("PersonalSign")
            {
                "EcSign" => SignatureType::EcSign as i32,
                _ => SignatureType::PersonalSign as i32,
            };
            let eth_input = EthMessageInput {
                message: input_json.message,
                signature_type,
            };
            let output: EthMessageOutput = keystore
                .sign_message(&sign_params, &eth_input)
                .map_err(to_js_err)?;
            serde_json::json!({ "signature": output.signature })
        }
    };

    keystore.lock();
    serde_json::to_string(&json_result).map_err(to_js_err)
}

fn encode_public_key(pk: &TypedPublicKey) -> String {
    pk.to_bytes().to_hex()
}

fn derive_message_key(
    keystore_json: Option<String>,
    prf_key: &str,
    derivation_path: Option<&str>,
) -> Result<secp256k1::SecretKey, JsValue> {
    let ks_json = resolve_keystore_json(keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&ks_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data, prf_key)?;
    let (mut keystore, _) = unlock_validated_keystore(&mnemonic, &ks_data)?;
    keystore.lock();
    let path = derivation_path.unwrap_or(nostr::DEFAULT_PATH);
    nostr::derive_secret_key(&mnemonic, path).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_message_key_pair(param_json: &str) -> Result<String, JsValue> {
    let param: MessageGetPubkeyParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = derive_message_key(
        param.keystore_json,
        &param.prf_key,
        param.derivation_path.as_deref(),
    )?;
    let pubkey = nostr::get_xonly_pubkey(&secret_key);
    CACHED_MESSAGE_SECRET_KEY.with(|cache| {
        *cache.borrow_mut() = Some(secret_key);
    });
    serde_json::to_string(&serde_json::json!({ "pubkey": pubkey.to_string() })).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_message_event(param_json: &str) -> Result<String, JsValue> {
    let param: MessageSignEventParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = get_cached_secret_key()?;
    let pubkey = nostr::get_xonly_pubkey(&secret_key);
    let pubkey_hex = pubkey.to_string();

    let event_id = nostr::compute_event_id(
        &pubkey_hex,
        param.event.created_at,
        param.event.kind,
        &param.event.tags,
        &param.event.content,
    );
    let sig = nostr::schnorr_sign(&secret_key, &event_id).map_err(to_js_err)?;

    let rumor = MessageSignedEvent {
        id: event_id.to_hex(),
        pubkey: pubkey_hex.clone(),
        created_at: param.event.created_at,
        kind: param.event.kind,
        tags: param.event.tags,
        content: param.event.content,
        sig: sig.to_hex(),
    };

    let recipient_pubkey = match param.recipient_pubkey {
        Some(pk) if !pk.is_empty() => pk,
        _ => return serde_json::to_string(&rumor).map_err(to_js_err),
    };

    // NIP-59 seal + wrap
    let recipient_pk = nostr::parse_pubkey(&recipient_pubkey).map_err(to_js_err)?;
    let now = param.event.created_at;
    const TWO_DAYS: u64 = 2 * 24 * 60 * 60;

    // Step 1: Seal (kind 13)
    let rumor_json = serde_json::to_string(&rumor).map_err(to_js_err)?;
    let seal_conv_key = nostr::get_conversation_key(&secret_key, &recipient_pk);
    let seal_content = nostr::nip44_encrypt(&seal_conv_key, &rumor_json).map_err(to_js_err)?;
    let seal_created_at = nostr::randomize_timestamp(now, TWO_DAYS);
    let seal_tags: Vec<Vec<String>> = vec![];
    let seal_event_id =
        nostr::compute_event_id(&pubkey_hex, seal_created_at, 13, &seal_tags, &seal_content);
    let seal_sig = nostr::schnorr_sign(&secret_key, &seal_event_id).map_err(to_js_err)?;
    let seal = MessageSignedEvent {
        id: seal_event_id.to_hex(),
        pubkey: pubkey_hex,
        created_at: seal_created_at,
        kind: 13,
        tags: seal_tags,
        content: seal_content,
        sig: seal_sig.to_hex(),
    };

    // Step 2: Wrap (kind 1059)
    let seal_json = serde_json::to_string(&seal).map_err(to_js_err)?;
    let ephemeral_sk = nostr::generate_random_secret_key().map_err(to_js_err)?;
    let ephemeral_pk = nostr::get_xonly_pubkey(&ephemeral_sk);
    let ephemeral_pk_hex = ephemeral_pk.to_string();
    let wrap_conv_key = nostr::get_conversation_key(&ephemeral_sk, &recipient_pk);
    let wrap_content = nostr::nip44_encrypt(&wrap_conv_key, &seal_json).map_err(to_js_err)?;
    let wrap_created_at = nostr::randomize_timestamp(now, TWO_DAYS);
    let wrap_tags = vec![vec!["p".to_string(), recipient_pubkey]];
    let wrap_event_id = nostr::compute_event_id(
        &ephemeral_pk_hex,
        wrap_created_at,
        1059,
        &wrap_tags,
        &wrap_content,
    );
    let wrap_sig = nostr::schnorr_sign(&ephemeral_sk, &wrap_event_id).map_err(to_js_err)?;
    let wrap = MessageSignedEvent {
        id: wrap_event_id.to_hex(),
        pubkey: ephemeral_pk_hex,
        created_at: wrap_created_at,
        kind: 1059,
        tags: wrap_tags,
        content: wrap_content,
        sig: wrap_sig.to_hex(),
    };

    serde_json::to_string(&wrap).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_message(param_json: &str) -> Result<String, JsValue> {
    let param: MessageEncryptParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = get_cached_secret_key()?;
    let server_pubkey = nostr::parse_pubkey(&param.server_pubkey).map_err(to_js_err)?;
    let conversation_key = nostr::get_conversation_key(&secret_key, &server_pubkey);
    let encrypted = nostr::nip44_encrypt(&conversation_key, &param.plaintext).map_err(to_js_err)?;
    serde_json::to_string(&serde_json::json!({ "encryptedContent": encrypted })).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_message(param_json: &str) -> Result<String, JsValue> {
    let param: MessageDecryptParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = get_cached_secret_key()?;
    let server_pubkey = nostr::parse_pubkey(&param.server_pubkey).map_err(to_js_err)?;
    let conversation_key = nostr::get_conversation_key(&secret_key, &server_pubkey);
    let plaintext =
        nostr::nip44_decrypt(&conversation_key, &param.encrypted_content).map_err(to_js_err)?;
    serde_json::to_string(&serde_json::json!({ "plaintext": plaintext })).map_err(to_js_err)
}

#[cfg(all(test, target_arch = "wasm32"))]
mod passkey_keystore_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PRF_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    fn create_test_keystore() -> PasskeyKeystore {
        let json = create_keystore(
            &serde_json::json!({
                "credentialId": "credential",
                "mnemonic": MNEMONIC,
                "prfKey": PRF_KEY,
                "rpId": "wallet.example",
                "userId": "user"
            })
            .to_string(),
        )
        .unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn mutate_hex(hex: &mut String) {
        let replacement = if hex.starts_with('0') { "1" } else { "0" };
        hex.replace_range(..1, replacement);
    }

    #[wasm_bindgen_test]
    fn aead_rejects_ciphertext_nonce_and_aad_tampering() {
        let keystore = create_test_keystore();
        assert_eq!(decrypt_mnemonic(&keystore, PRF_KEY).unwrap(), MNEMONIC);

        let mut mutations: Vec<Box<dyn Fn(&mut PasskeyKeystore)>> = vec![
            Box::new(|ks| mutate_hex(&mut ks.encrypted_mnemonic)),
            Box::new(|ks| mutate_hex(&mut ks.mnemonic_nonce)),
            Box::new(|ks| ks.user_id.push('x')),
            Box::new(|ks| ks.credential_id.push('x')),
            Box::new(|ks| ks.rp_id.push('x')),
            Box::new(|ks| ks.identity.identifier.push('x')),
        ];

        for mutation in mutations.drain(..) {
            let mut tampered: PasskeyKeystore =
                serde_json::from_str(&serde_json::to_string(&keystore).unwrap()).unwrap();
            mutation(&mut tampered);
            assert!(decrypt_mnemonic(&tampered, PRF_KEY).is_err());
        }
    }

    #[wasm_bindgen_test]
    fn legacy_keystore_migrates_only_after_identity_validation() {
        let prf_key = parse_prf_key(PRF_KEY).unwrap();
        let iv = [3u8; 16];
        let encrypted =
            tcx_crypto::aes::ctr::encrypt_nopadding(MNEMONIC.as_bytes(), &prf_key[..16], &iv)
                .unwrap();
        let keystore =
            Keystore::from_mnemonic(MNEMONIC, "", passkey_metadata(IdentityNetwork::Mainnet))
                .unwrap();
        let legacy = PasskeyKeystore {
            version: 0,
            cipher: String::new(),
            user_id: "user".to_string(),
            credential_id: "credential".to_string(),
            rp_id: "wallet.example".to_string(),
            encrypted_mnemonic: encrypted.to_hex(),
            mnemonic_iv: iv.to_hex(),
            mnemonic_nonce: String::new(),
            network: String::new(),
            created_at: 1,
            identity: keystore.store().identity.clone(),
        };
        let legacy_json = serde_json::to_string(&legacy).unwrap();
        let migrated_json = migrate_keystore(
            &serde_json::json!({ "keystoreJson": legacy_json, "prfKey": PRF_KEY }).to_string(),
        )
        .unwrap();
        let migrated: PasskeyKeystore = serde_json::from_str(&migrated_json).unwrap();

        assert_eq!(migrated.version, PASSKEY_KEYSTORE_VERSION);
        assert!(migrated.mnemonic_iv.is_empty());
        assert_eq!(decrypt_mnemonic(&migrated, PRF_KEY).unwrap(), MNEMONIC);

        let mut invalid_legacy = legacy;
        invalid_legacy.identity.identifier.push('x');
        assert!(migrate_keystore(
            &serde_json::json!({
                "keystoreJson": serde_json::to_string(&invalid_legacy).unwrap(),
                "prfKey": PRF_KEY
            })
            .to_string()
        )
        .is_err());
    }
}
