use std::cell::RefCell;

use secp256k1::SecretKey;
use wasm_bindgen::prelude::*;

mod nostr;
mod types;

use tcx_btc_kin::transaction::{
    BtcKinTxInput, BtcKinTxOutput, BtcMessageInput, BtcMessageOutput, PsbtInput, PsbtOutput,
    PsbtsInput, PsbtsOutput, Utxo as BtcUtxo,
};
use tcx_btc_kin::{sign_psbt as btc_sign_psbt, sign_psbts as btc_sign_psbts, BtcKinAddress};
use tcx_common::{random_u8_16, FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_eth::address::EthAddress;
use tcx_eth::transaction::{
    AccessList as ProtoAccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
    SignatureType,
};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::{IdentityNetwork, Metadata};
use tcx_keystore::{
    mnemonic_to_seed, Keystore, MessageSigner, SignatureParameters, TransactionSigner,
};
use tcx_primitive::{mnemonic_from_entropy, TypedPublicKey};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use tcx_tron::TronAddress;

use types::*;

const PBKDF2_ROUNDS: i32 = 600_000;

fn set_pbkdf2_rounds() {
    let mut rounds = tcx_crypto::KDF_ROUNDS.write();
    *rounds = PBKDF2_ROUNDS;
}

thread_local! {
    static CACHED_KEYSTORE_JSON: RefCell<Option<String>> = const { RefCell::new(None) };
    static CACHED_MESSAGE_SECRET_KEY: RefCell<Option<SecretKey>> = const { RefCell::new(None) };
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

fn resolve_key(key: Option<String>, legacy_prf_key: Option<String>) -> Result<String, String> {
    match (key, legacy_prf_key) {
        (Some(_), Some(_)) => Err("key and prfKey are ambiguous; use key".to_string()),
        (Some(key), None) | (None, Some(key)) if !key.is_empty() => Ok(key),
        _ => Err("key must be provided".to_string()),
    }
}

fn has_native_crypto(keystore_json: &str) -> Result<bool, JsValue> {
    let value: serde_json::Value = serde_json::from_str(keystore_json).map_err(to_js_err)?;
    if value.get("crypto").is_some() {
        return Ok(true);
    }
    if value.get("encryptedMnemonic").is_some() && value.get("mnemonicIv").is_some() {
        return Ok(false);
    }
    Err(JsValue::from_str("unsupported keystore format"))
}

fn unlock_keystore_with_key(keystore_json: String, key: String) -> Result<Keystore, JsValue> {
    if has_native_crypto(&keystore_json)? {
        let mut keystore = Keystore::from_json(&keystore_json).map_err(to_js_err)?;
        keystore.unlock_by_password(&key).map_err(to_js_err)?;
        return Ok(keystore);
    }

    let ks_data: PasskeyKeystore = serde_json::from_str(&keystore_json).map_err(to_js_err)?;
    let mnemonic = decrypt_mnemonic(&ks_data.encrypted_mnemonic, &ks_data.mnemonic_iv, &key)?;
    unlock_keystore_from_mnemonic(&mnemonic)
}

fn default_btc_full_path(seg_wit: &str) -> &'static str {
    match seg_wit {
        "P2WPKH" => "m/49'/0'/0'/0/0",
        "VERSION_0" => "m/84'/0'/0'/0/0",
        "VERSION_1" => "m/86'/0'/0'/0/0",
        _ => "m/44'/0'/0'/0/0",
    }
}

fn btc_account_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 2 {
        parts[..parts.len() - 2].join("/")
    } else {
        path.to_string()
    }
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

    let network = match param.network.as_deref() {
        Some("TESTNET") => IdentityNetwork::Testnet,
        _ => IdentityNetwork::Mainnet,
    };

    match (param.prf_key, param.password) {
        (Some(_), Some(_)) | (None, None) => Err(JsValue::from_str(
            "exactly one of prfKey or password must be provided",
        )),
        (Some(prf_key_hex), None) => {
            let prf_key = Vec::from_hex(&prf_key_hex).map_err(to_js_err)?;
            if prf_key.len() != 32 {
                return Err(JsValue::from_str("PRF key must be 32 bytes"));
            }

            let iv = random_u8_16();
            let encrypted =
                tcx_crypto::aes::ctr256::encrypt_nopadding(mnemonic.as_bytes(), &prf_key, &iv)
                    .map_err(to_js_err)?;

            let seed = mnemonic_to_seed(&mnemonic).map_err(to_js_err)?;
            let identity =
                Identity::from_seed_with_raw_key(&seed, &prf_key, &network).map_err(to_js_err)?;

            let result = PasskeyKeystore {
                user_id: param
                    .user_id
                    .ok_or_else(|| JsValue::from_str("userId must be provided for prfKey"))?,
                credential_id: param
                    .credential_id
                    .ok_or_else(|| JsValue::from_str("credentialId must be provided for prfKey"))?,
                rp_id: param
                    .rp_id
                    .ok_or_else(|| JsValue::from_str("rpId must be provided for prfKey"))?,
                encrypted_mnemonic: encrypted.to_hex(),
                mnemonic_iv: iv.to_hex(),
                created_at: now_timestamp(),
                identity,
            };

            serde_json::to_string(&result).map_err(to_js_err)
        }
        (None, Some(password)) => {
            if password.is_empty() {
                return Err(JsValue::from_str("password must be provided"));
            }

            set_pbkdf2_rounds();

            let metadata = Metadata {
                network,
                ..Metadata::default()
            };
            let keystore =
                Keystore::from_mnemonic(&mnemonic, &password, metadata).map_err(to_js_err)?;
            Ok(keystore.to_json())
        }
    }
}

#[wasm_bindgen]
pub fn derive_accounts(param_json: &str) -> Result<String, JsValue> {
    let param: DeriveAccountsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    if param.derivations.is_empty() {
        return Err(JsValue::from_str("derivations must not be empty"));
    }

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;

    let mut results: Vec<AccountResponse> = Vec::with_capacity(param.derivations.len());

    for item in &param.derivations {
        let chain = item.chain.as_deref().unwrap_or("ETHEREUM");
        let coin_name = match chain {
            "TRON" => "TRON",
            "BITCOIN" => "BITCOIN",
            _ => "ETHEREUM",
        };

        let coin_info = tcx_constants::CoinInfo {
            chain_id: item.chain_id.clone().unwrap_or_default(),
            coin: coin_name.to_string(),
            derivation_path: item.derivation_path.clone(),
            curve: CurveType::SECP256k1,
            network: item.network.as_deref().unwrap_or("MAINNET").to_string(),
            seg_wit: item.seg_wit.clone().unwrap_or_default(),
            contract_code: "".to_string(),
        };

        let account = match chain {
            "TRON" => keystore
                .derive_coin::<TronAddress>(&coin_info)
                .map_err(to_js_err)?,
            "BITCOIN" => keystore
                .derive_coin::<BtcKinAddress>(&coin_info)
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

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;
    let mnemonic = keystore.export().map_err(to_js_err)?;
    keystore.lock();
    serde_json::to_string(&serde_json::json!({ "mnemonic": mnemonic })).map_err(to_js_err)
}

fn sign_single_tx(
    keystore: &mut Keystore,
    chain: &str,
    derivation_path: Option<String>,
    network: Option<String>,
    seg_wit: Option<String>,
    input: serde_json::Value,
) -> Result<serde_json::Value, JsValue> {
    let seg_wit = seg_wit.unwrap_or_default();
    let default_path = match chain {
        "TRON" => "m/44'/195'/0'/0/0",
        "BITCOIN" => default_btc_full_path(&seg_wit),
        _ => "m/44'/60'/0'/0/0",
    };

    let derivation_path = derivation_path.unwrap_or_else(|| default_path.to_string());

    let sign_params = SignatureParameters {
        curve: CurveType::SECP256k1,
        derivation_path,
        chain_type: chain.to_string(),
        network: network.unwrap_or_else(|| "MAINNET".to_string()),
        seg_wit: seg_wit.clone(),
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
        "BITCOIN" => {
            let btc_input_json: BtcTxInputJson =
                serde_json::from_value(input).map_err(to_js_err)?;
            let btc_input = BtcKinTxInput {
                inputs: btc_input_json
                    .inputs
                    .into_iter()
                    .map(|u| BtcUtxo {
                        tx_hash: u.tx_hash,
                        vout: u.vout,
                        amount: u.amount,
                        address: u.address,
                        derived_path: u.derived_path,
                    })
                    .collect(),
                to: btc_input_json.to,
                amount: btc_input_json.amount,
                fee: btc_input_json.fee,
                op_return: btc_input_json.op_return,
                change_address_index: btc_input_json.change_address_index,
            };
            let output: BtcKinTxOutput = keystore
                .sign_transaction(&sign_params, &btc_input)
                .map_err(to_js_err)?;
            Ok(serde_json::json!({
                "rawTx": output.raw_tx,
                "txHash": output.tx_hash,
                "wtxHash": output.wtx_hash,
            }))
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

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;
    let chain = param.chain.as_deref().unwrap_or("ETHEREUM");
    let json_result = sign_single_tx(
        &mut keystore,
        chain,
        param.derivation_path,
        param.network,
        param.seg_wit,
        param.input,
    )?;

    keystore.lock();
    serde_json::to_string(&json_result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_txs(param_json: &str) -> Result<String, JsValue> {
    let param: SignTxsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    if param.txs.is_empty() {
        return Err(JsValue::from_str("txs must not be empty"));
    }

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;

    let mut results: Vec<serde_json::Value> = Vec::with_capacity(param.txs.len());
    for tx in param.txs {
        let chain = tx.chain.as_deref().unwrap_or("ETHEREUM");
        let result = sign_single_tx(
            &mut keystore,
            chain,
            tx.derivation_path,
            tx.network,
            tx.seg_wit,
            tx.input,
        )?;
        results.push(result);
    }

    keystore.lock();
    serde_json::to_string(&results).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_message(param_json: &str) -> Result<String, JsValue> {
    let param: SignMessageParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;

    let chain = param.chain.as_deref().unwrap_or("ETHEREUM");
    let seg_wit = param.seg_wit.clone().unwrap_or_default();
    let default_path = match chain {
        "TRON" => "m/44'/195'/0'/0/0".to_string(),
        "BITCOIN" => btc_account_path(default_btc_full_path(&seg_wit)),
        _ => "m/44'/60'/0'/0/0".to_string(),
    };

    let derivation_path = match (chain, param.derivation_path) {
        ("BITCOIN", Some(p)) => btc_account_path(&p),
        (_, Some(p)) => p,
        (_, None) => default_path,
    };

    let sign_params = SignatureParameters {
        curve: CurveType::SECP256k1,
        derivation_path,
        chain_type: chain.to_string(),
        network: param.network.unwrap_or_else(|| "MAINNET".to_string()),
        seg_wit: seg_wit.clone(),
    };

    let json_result = match chain {
        "BITCOIN" => {
            let input_json: BtcSignMessageInputJson =
                serde_json::from_value(param.input).map_err(to_js_err)?;
            let btc_input = BtcMessageInput {
                message: input_json.message,
            };
            let output: BtcMessageOutput = keystore
                .sign_message(&sign_params, &btc_input)
                .map_err(to_js_err)?;
            serde_json::json!({ "signature": output.signature })
        }
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

#[wasm_bindgen]
pub fn sign_psbt(param_json: &str) -> Result<String, JsValue> {
    let param: SignPsbtParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;

    let chain = param.chain.as_deref().unwrap_or("BITCOIN");
    let derivation_path = btc_account_path(&param.derivation_path);

    let psbt_input = PsbtInput {
        psbt: param.input.psbt,
        auto_finalize: param.input.auto_finalize,
    };
    let output: PsbtOutput =
        btc_sign_psbt(chain, &derivation_path, &mut keystore, psbt_input).map_err(to_js_err)?;

    keystore.lock();
    serde_json::to_string(&serde_json::json!({ "psbt": output.psbt })).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_psbts(param_json: &str) -> Result<String, JsValue> {
    let param: SignPsbtsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let keystore_json = resolve_keystore_json(param.keystore_json)?;
    let mut keystore = unlock_keystore_with_key(keystore_json, key)?;

    let chain = param.chain.as_deref().unwrap_or("BITCOIN");
    let derivation_path = btc_account_path(&param.derivation_path);

    let psbts_input = PsbtsInput {
        psbts: param.input.psbts,
        auto_finalize: param.input.auto_finalize,
    };
    let output: PsbtsOutput =
        btc_sign_psbts(chain, &derivation_path, &mut keystore, psbts_input).map_err(to_js_err)?;

    keystore.lock();
    serde_json::to_string(&serde_json::json!({ "psbts": output.psbts })).map_err(to_js_err)
}

fn encode_public_key(pk: &TypedPublicKey) -> String {
    pk.to_bytes().to_hex()
}

fn derive_message_key(
    keystore_json: Option<String>,
    key: String,
    derivation_path: Option<&str>,
) -> Result<secp256k1::SecretKey, JsValue> {
    let ks_json = resolve_keystore_json(keystore_json)?;
    let mut keystore = unlock_keystore_with_key(ks_json, key)?;
    let mnemonic = keystore.export().map_err(to_js_err)?;
    keystore.lock();
    let path = derivation_path.unwrap_or(nostr::DEFAULT_PATH);
    nostr::derive_secret_key(&mnemonic, path).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_message_key_pair(param_json: &str) -> Result<String, JsValue> {
    let param: MessageGetPubkeyParam = serde_json::from_str(param_json).map_err(to_js_err)?;
    let key = resolve_key(param.key, param.prf_key).map_err(to_js_err)?;
    let secret_key =
        derive_message_key(param.keystore_json, key, param.derivation_path.as_deref())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "inject kidney empty canal shadow pact comfort wife crush horse wife sketch";
    const TEST_PRF_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const TEST_PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn resolve_key_rejects_missing_or_ambiguous_inputs() {
        assert!(resolve_key(None, None).is_err());
        assert!(resolve_key(Some("new-key".to_string()), Some("legacy-key".to_string())).is_err());
        assert_eq!(
            resolve_key(Some("new-key".to_string()), None).unwrap(),
            "new-key"
        );
        assert_eq!(
            resolve_key(None, Some("legacy-key".to_string())).unwrap(),
            "legacy-key"
        );
    }

    #[test]
    fn create_keystore_with_password_returns_native_hd_keystore() {
        let keystore_json = create_keystore(
            &serde_json::json!({
                "password": TEST_PASSWORD,
                "mnemonic": TEST_MNEMONIC,
                "network": "MAINNET"
            })
            .to_string(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&keystore_json).unwrap();

        assert_eq!(value["version"], 12000);
        assert_eq!(value["crypto"]["kdf"], "pbkdf2");
        assert_eq!(value["crypto"]["kdfparams"]["c"], 600_000);
        assert_eq!(value["imTokenMeta"]["network"], "MAINNET");
    }

    #[test]
    fn export_mnemonic_unlocks_password_keystore_with_key() {
        let keystore_json = create_keystore(
            &serde_json::json!({
                "password": TEST_PASSWORD,
                "mnemonic": TEST_MNEMONIC
            })
            .to_string(),
        )
        .unwrap();

        let exported = export_mnemonic(
            &serde_json::json!({
                "keystoreJson": keystore_json,
                "key": TEST_PASSWORD
            })
            .to_string(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(value["mnemonic"], TEST_MNEMONIC);
    }

    #[test]
    fn export_mnemonic_unlocks_passkey_keystore_with_key() {
        let prf_key = Vec::from_hex(TEST_PRF_KEY).unwrap();
        let iv = [0u8; 16];
        let encrypted =
            tcx_crypto::aes::ctr256::encrypt_nopadding(TEST_MNEMONIC.as_bytes(), &prf_key, &iv)
                .unwrap();
        let passkey_keystore = PasskeyKeystore {
            user_id: "test-user".to_string(),
            credential_id: "test-credential".to_string(),
            rp_id: "localhost".to_string(),
            encrypted_mnemonic: encrypted.to_hex(),
            mnemonic_iv: iv.to_hex(),
            created_at: 1,
            identity: Identity::default(),
        };
        let keystore_json = serde_json::to_string(&passkey_keystore).unwrap();

        let exported = export_mnemonic(
            &serde_json::json!({
                "keystoreJson": keystore_json,
                "key": TEST_PRF_KEY
            })
            .to_string(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(value["mnemonic"], TEST_MNEMONIC);
    }
}
