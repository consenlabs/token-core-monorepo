use std::cell::RefCell;

use secp256k1::SecretKey;
use wasm_bindgen::prelude::*;

mod nostr;
mod types;

use tcx_common::{random_u8_16, FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_eth::address::EthAddress;
use tcx_eth::transaction::{
    AccessList as ProtoAccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
    SignatureType,
};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::IdentityNetwork;
use tcx_keystore::{
    mnemonic_to_seed, Keystore, MessageSigner, SignatureParameters, TransactionSigner,
};
use tcx_primitive::{mnemonic_from_entropy, TypedPublicKey};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use tcx_tron::TronAddress;

use types::*;

thread_local! {
    static CACHED_KEYSTORE_JSON: RefCell<Option<String>> = const { RefCell::new(None) };
    static CACHED_MESSAGE_SECRET_KEY: RefCell<Option<SecretKey>> = RefCell::new(None);
}

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

fn decrypt_mnemonic(
    encrypted_mnemonic: &str,
    iv_hex: &str,
    prf_key_hex: &str,
) -> Result<String, JsValue> {
    let key = Vec::from_hex(prf_key_hex).map_err(to_js_err)?;
    if key.len() != 32 {
        return Err(JsValue::from_str("PRF key must be 32 bytes"));
    }
    let iv = Vec::from_hex(iv_hex).map_err(to_js_err)?;
    let encrypted = Vec::from_hex(encrypted_mnemonic).map_err(to_js_err)?;
    let decrypted =
        tcx_crypto::aes::ctr256::decrypt_nopadding(&encrypted, &key, &iv).map_err(to_js_err)?;
    String::from_utf8(decrypted).map_err(to_js_err)
}

fn unlock_keystore_from_mnemonic(mnemonic: &str) -> Result<Keystore, JsValue> {
    Keystore::from_mnemonic_unlocked(mnemonic).map_err(to_js_err)
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

    let prf_key = Vec::from_hex(&param.prf_key).map_err(to_js_err)?;
    if prf_key.len() != 32 {
        return Err(JsValue::from_str("PRF key must be 32 bytes"));
    }

    let mnemonic = if let Some(m) = param.mnemonic {
        m
    } else {
        let entropy = if let Some(entropy_hex) = param.entropy {
            Vec::from_hex(&entropy_hex).map_err(to_js_err)?
        } else {
            random_u8_16().to_vec()
        };
        mnemonic_from_entropy(&entropy).map_err(to_js_err)?
    };

    let iv = random_u8_16();
    let encrypted = tcx_crypto::aes::ctr256::encrypt_nopadding(mnemonic.as_bytes(), &prf_key, &iv)
        .map_err(to_js_err)?;

    let network = match param.network.as_deref() {
        Some("TESTNET") => IdentityNetwork::Testnet,
        _ => IdentityNetwork::Mainnet,
    };
    let seed = mnemonic_to_seed(&mnemonic).map_err(to_js_err)?;
    let identity =
        Identity::from_seed_with_raw_key(&seed, &prf_key, &network).map_err(to_js_err)?;

    let result = PasskeyKeystore {
        user_id: param.user_id,
        credential_id: param.credential_id,
        rp_id: param.rp_id,
        encrypted_mnemonic: encrypted.to_hex(),
        mnemonic_iv: iv.to_hex(),
        created_at: now_timestamp(),
        identity,
    };

    serde_json::to_string(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_accounts(param_json: &str) -> Result<String, JsValue> {
    let param: DeriveAccountsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    if param.derivations.is_empty() {
        return Err(JsValue::from_str("derivations must not be empty"));
    }

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(
        &ks_data.encrypted_mnemonic,
        &ks_data.mnemonic_iv,
        &param.prf_key,
    )?;

    let mut keystore = unlock_keystore_from_mnemonic(&mnemonic)?;

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
pub fn sign_tx(param_json: &str) -> Result<String, JsValue> {
    let param: SignTxParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(
        &ks_data.encrypted_mnemonic,
        &ks_data.mnemonic_iv,
        &param.prf_key,
    )?;

    let mut keystore = unlock_keystore_from_mnemonic(&mnemonic)?;

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
            let tron_input_json: TronTxInputJson =
                serde_json::from_value(param.input).map_err(to_js_err)?;
            let tron_input = TronTxInput {
                raw_data: tron_input_json.raw_data,
            };
            let output: TronTxOutput = keystore
                .sign_transaction(&sign_params, &tron_input)
                .map_err(to_js_err)?;
            serde_json::json!({ "signatures": output.signatures })
        }
        _ => {
            let eth_input_json: EthTxInputJson =
                serde_json::from_value(param.input).map_err(to_js_err)?;
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
            serde_json::json!({
                "signature": output.signature,
                "txHash": output.tx_hash,
            })
        }
    };

    keystore.lock();
    serde_json::to_string(&json_result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_message(param_json: &str) -> Result<String, JsValue> {
    let param: SignMessageParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(
        &ks_data.encrypted_mnemonic,
        &ks_data.mnemonic_iv,
        &param.prf_key,
    )?;

    let mut keystore = unlock_keystore_from_mnemonic(&mnemonic)?;

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
    let mnemonic = decrypt_mnemonic(&ks_data.encrypted_mnemonic, &ks_data.mnemonic_iv, prf_key)?;
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
    let secret_key = derive_message_key(
        param.keystore_json,
        &param.prf_key,
        param.derivation_path.as_deref(),
    )?;
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

    let result = MessageSignedEvent {
        id: event_id.to_hex(),
        pubkey: pubkey_hex,
        created_at: param.event.created_at,
        kind: param.event.kind,
        tags: param.event.tags,
        content: param.event.content,
        sig: sig.to_hex(),
    };
    serde_json::to_string(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_message(param_json: &str) -> Result<String, JsValue> {
    let param: MessageEncryptParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = get_cached_secret_key()?;
    let server_pubkey = nostr::parse_pubkey(nostr::SERVER_PUBKEY).map_err(to_js_err)?;
    let conversation_key = nostr::get_conversation_key(&secret_key, &server_pubkey);
    let encrypted = nostr::nip44_encrypt(&conversation_key, &param.plaintext).map_err(to_js_err)?;
    serde_json::to_string(&serde_json::json!({ "encryptedContent": encrypted })).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_message(param_json: &str) -> Result<String, JsValue> {
    let param: MessageDecryptParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let secret_key = get_cached_secret_key()?;
    let server_pubkey = nostr::parse_pubkey(nostr::SERVER_PUBKEY).map_err(to_js_err)?;
    let conversation_key = nostr::get_conversation_key(&secret_key, &server_pubkey);
    let plaintext =
        nostr::nip44_decrypt(&conversation_key, &param.encrypted_content).map_err(to_js_err)?;
    serde_json::to_string(&serde_json::json!({ "plaintext": plaintext })).map_err(to_js_err)
}
