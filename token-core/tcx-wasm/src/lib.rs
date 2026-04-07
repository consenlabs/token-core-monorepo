use wasm_bindgen::prelude::*;

mod types;

use tcx_common::ToHex;
use tcx_constants::CurveType;
use tcx_eth::address::EthAddress;
use tcx_eth::transaction::{AccessList as ProtoAccessList, EthTxInput, EthTxOutput};
use tcx_keystore::{
    HdKeystore, Keystore, Metadata, SignatureParameters, Source, TransactionSigner,
};
use tcx_primitive::TypedPublicKey;

use types::*;

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
pub fn create_keystore(param_json: &str) -> Result<String, JsValue> {
    let param: CreateKeystoreParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let meta = Metadata {
        name: param.name.unwrap_or_else(|| "Unknown".to_string()),
        password_hint: param.password_hint,
        source: if param.mnemonic.is_some() {
            Source::Mnemonic
        } else {
            Source::NewMnemonic
        },
        ..Metadata::default()
    };

    let keystore = if let Some(mnemonic) = &param.mnemonic {
        Keystore::from_mnemonic(mnemonic, &param.password, meta).map_err(to_js_err)?
    } else {
        Keystore::Hd(HdKeystore::new(&param.password, meta))
    };

    let result = KeystoreResult {
        id: keystore.id(),
        name: keystore.meta().name,
        source: keystore.meta().source.to_string(),
        created_at: keystore.meta().timestamp,
        keystore_json: keystore.to_json(),
    };

    serde_json::to_string(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_accounts(param_json: &str) -> Result<String, JsValue> {
    let param: DeriveAccountsParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let mut keystore = Keystore::from_json(&param.keystore_json).map_err(to_js_err)?;
    keystore
        .unlock_by_password(&param.password)
        .map_err(to_js_err)?;

    let derivation_path = param
        .derivation_path
        .unwrap_or_else(|| "m/44'/60'/0'/0/0".to_string());

    let coin_info = tcx_constants::CoinInfo {
        chain_id: param.chain_id.unwrap_or_default(),
        coin: "ETHEREUM".to_string(),
        derivation_path,
        curve: CurveType::SECP256k1,
        network: param.network.unwrap_or_else(|| "MAINNET".to_string()),
        seg_wit: "".to_string(),
        contract_code: "".to_string(),
    };

    let account = keystore
        .derive_coin::<EthAddress>(&coin_info)
        .map_err(to_js_err)?;

    let result = AccountResponse {
        address: account.address,
        derivation_path: account.derivation_path,
        ext_pub_key: account.ext_pub_key,
        public_key: encode_public_key(&account.public_key),
    };

    keystore.lock();
    serde_json::to_string(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sign_tx(param_json: &str) -> Result<String, JsValue> {
    let param: SignTxParam = serde_json::from_str(param_json).map_err(to_js_err)?;

    let mut keystore = Keystore::from_json(&param.keystore_json).map_err(to_js_err)?;
    keystore
        .unlock_by_password(&param.password)
        .map_err(to_js_err)?;

    let derivation_path = param
        .derivation_path
        .unwrap_or_else(|| "m/44'/60'/0'/0/0".to_string());

    let sign_params = SignatureParameters {
        curve: CurveType::SECP256k1,
        derivation_path,
        chain_type: "ETHEREUM".to_string(),
        network: "".to_string(),
        seg_wit: "".to_string(),
    };

    let access_list: Vec<ProtoAccessList> = param
        .input
        .access_list
        .unwrap_or_default()
        .into_iter()
        .map(|item| ProtoAccessList {
            address: item.address,
            storage_keys: item.storage_keys,
        })
        .collect();

    let eth_input = EthTxInput {
        nonce: param.input.nonce,
        gas_price: param.input.gas_price.unwrap_or_default(),
        gas_limit: param.input.gas_limit,
        to: param.input.to,
        value: param.input.value,
        data: param.input.data.unwrap_or_default(),
        chain_id: param.input.chain_id,
        tx_type: param.input.tx_type.unwrap_or_default(),
        max_fee_per_gas: param.input.max_fee_per_gas.unwrap_or_default(),
        max_priority_fee_per_gas: param.input.max_priority_fee_per_gas.unwrap_or_default(),
        access_list,
    };

    let output: EthTxOutput = keystore
        .sign_transaction(&sign_params, &eth_input)
        .map_err(to_js_err)?;

    keystore.lock();

    let result = SignTxResult {
        signature: output.signature,
        tx_hash: output.tx_hash,
    };

    serde_json::to_string(&result).map_err(to_js_err)
}

fn encode_public_key(pk: &TypedPublicKey) -> String {
    pk.to_bytes().to_hex()
}
