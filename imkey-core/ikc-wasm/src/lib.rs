use std::cell::RefCell;

use bitcoin::bip32::Xpub;
use bitcoin::Network;
use coin_bch::address::BchAddress;
use coin_bch::transaction::{BchTransaction, Utxo as BchUtxo};
use coin_bitcoin::address::BtcAddress;
use coin_bitcoin::btc_kin_address::AddressTrait;
use coin_bitcoin::btc_kin_address::BtcKinAddress;
use coin_bitcoin::btcapi::{BtcMessageInput, BtcSignatureType, PsbtInput};
use coin_bitcoin::message::MessageSinger;
use coin_bitcoin::network::BtcKinNetwork;
use coin_bitcoin::psbt::sign_psbt_async;
use coin_bitcoin::transaction::{BtcTransaction, Utxo as BtcUtxo};
use coin_btc_fork::address::BtcForkAddress;
use coin_btc_fork::btc_fork_network::network_from_param;
use coin_btc_fork::btcforkapi::{BtcForkTxInput, Utxo as BtcForkUtxo};
use coin_btc_fork::transaction::BtcForkTransaction;
use coin_ckb::address::CkbAddress;
use coin_ckb::signer::CkbSigner;
use coin_ckb::{
    CachedCell as CkbCachedCell, CellInput as CkbCellInput, CkbTxInput, OutPoint as CkbOutPoint,
    Script as CkbScript, Witness as CkbWitness,
};
use coin_cosmos::address::CosmosAddress;
use coin_cosmos::transaction::CosmosTransaction;
use coin_eos::eosapi::{EosMessageInput, EosSignData, EosTxInput};
use coin_eos::pubkey::EosPubkey;
use coin_eos::transaction::EosTransaction;
use coin_ethereum::address::EthAddress;
use coin_ethereum::ethapi::EthMessageInput;
use coin_ethereum::transaction::{AccessListItem, Transaction as EthTransaction};
use coin_ethereum::types::Action as EthAction;
use coin_filecoin::address::FilecoinAddress;
use coin_filecoin::filecoinapi::FilecoinTxInput;
use coin_filecoin::transaction::Transaction as FilecoinTransaction;
use coin_substrate::address::{AddressType as SubstrateAddressType, SubstrateAddress};
use coin_substrate::substrateapi::SubstrateRawTxIn;
use coin_substrate::transaction::Transaction as SubstrateTransaction;
use coin_tezos::address::TezosAddress;
use coin_tezos::tezosapi::TezosTxInput;
use coin_tezos::transaction::Transaction as TezosTransaction;
use coin_tron::address::TronAddress;
use coin_tron::signer::TronSigner;
use coin_tron::tronapi::{TronMessageInput, TronTxInput};
use ethereum_types::{Address as EthRawAddress, H256, U256};
use ikc_common::coin_info::coin_info_from_param;
use ikc_common::path::get_account_path;
use ikc_common::utility::{
    encrypt_xpub, extended_pub_key_derive, from_ss58check_with_version, get_xpub_prefix,
    to_ss58check_with_version, uncompress_pubkey_2_compress,
};
use ikc_common::{SignParam, ToHex};
use ikc_device::async_device_manager::{
    self, AsyncApduTransport, AsyncBindingStorage, AsyncTsmClient, BoxFutureResult,
    TransportProfile,
};
use js_sys::{Function, Promise, Reflect};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

thread_local! {
    static TRANSPORT: RefCell<Option<JsValue>> = const { RefCell::new(None) };
    static TSM_CLIENT: RefCell<Option<JsValue>> = const { RefCell::new(None) };
    static BINDING_STORAGE: RefCell<Option<JsValue>> = const { RefCell::new(None) };
    static TRANSPORT_PROFILE: RefCell<TransportProfile> = const { RefCell::new(TransportProfile::WebUsb) };
}

fn js_err(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn js_value_message(value: &JsValue, fallback: &str) -> String {
    if let Some(message) = value.as_string() {
        return message;
    }
    Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn map_err(error: anyhow::Error) -> JsValue {
    js_err(error.to_string())
}

fn normalize_hex(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn transport() -> Result<JsValue, JsValue> {
    TRANSPORT.with(|transport| {
        transport
            .borrow()
            .clone()
            .ok_or_else(|| js_err("imkey_transport_not_set"))
    })
}

fn tsm_client() -> Result<JsValue, JsValue> {
    TSM_CLIENT.with(|client| {
        client
            .borrow()
            .clone()
            .ok_or_else(|| js_err("imkey_tsm_client_not_set"))
    })
}

fn binding_storage() -> Result<JsValue, JsValue> {
    BINDING_STORAGE.with(|storage| {
        storage
            .borrow()
            .clone()
            .ok_or_else(|| js_err("imkey_binding_storage_not_set"))
    })
}

fn transport_profile() -> TransportProfile {
    TRANSPORT_PROFILE.with(|profile| *profile.borrow())
}

fn parse_transport_profile(value: &str) -> Result<TransportProfile, JsValue> {
    match value.trim().to_ascii_lowercase().as_str() {
        "webusb" | "web_usb" => Ok(TransportProfile::WebUsb),
        "webhid" | "web_hid" => Ok(TransportProfile::WebHid),
        "ble" | "bluetooth" => Ok(TransportProfile::Ble),
        "hid" | "native_hid" => Ok(TransportProfile::NativeHid),
        _ => Err(js_err("imkey_unknown_transport_profile")),
    }
}

async fn call_transport(apdu: &str, timeout_ms: Option<u32>) -> Result<String, JsValue> {
    let transport = transport()?;
    let method = Reflect::get(&transport, &JsValue::from_str("sendApduRaw"))?;
    let method = method
        .dyn_ref::<Function>()
        .ok_or_else(|| js_err("transport.sendApduRaw is not a function"))?;

    let promise = match timeout_ms {
        Some(timeout_ms) => method.call2(
            &transport,
            &JsValue::from_str(apdu),
            &JsValue::from_f64(timeout_ms as f64),
        )?,
        None => method.call1(&transport, &JsValue::from_str(apdu))?,
    };
    let promise = promise
        .dyn_into::<Promise>()
        .map_err(|_| js_err("transport.sendApduRaw must return a Promise"))?;
    let response = JsFuture::from(promise).await?;
    response
        .as_string()
        .map(|value| normalize_hex(&value))
        .ok_or_else(|| js_err("transport response must be a hex string"))
}

async fn call_tsm(action: &str, body_json: &str) -> Result<String, JsValue> {
    let client = tsm_client()?;
    let method = Reflect::get(&client, &JsValue::from_str("post"))?;
    let method = method
        .dyn_ref::<Function>()
        .ok_or_else(|| js_err("tsmClient.post is not a function"))?;

    let promise = method.call2(
        &client,
        &JsValue::from_str(action),
        &JsValue::from_str(body_json),
    )?;
    let promise = promise
        .dyn_into::<Promise>()
        .map_err(|_| js_err("tsmClient.post must return a Promise"))?;
    let response = JsFuture::from(promise).await?;
    response
        .as_string()
        .ok_or_else(|| js_err("tsm client response must be a string"))
}

struct JsApduTransport {
    profile: TransportProfile,
}

impl AsyncApduTransport for JsApduTransport {
    fn profile(&self) -> TransportProfile {
        self.profile
    }

    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String> {
        Box::pin(async move {
            let timeout_ms = timeout.max(1) as u32 * 1000;
            call_transport(apdu, Some(timeout_ms))
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_send_apdu_error")))
        })
    }
}

struct JsTsmClient;

impl AsyncTsmClient for JsTsmClient {
    fn post<'a>(&'a self, action: &'a str, body: Vec<u8>) -> BoxFutureResult<'a, String> {
        Box::pin(async move {
            let body_json = String::from_utf8(body)?;
            call_tsm(action, &body_json)
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_tsm_request_error")))
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressParamJson {
    chain_type: String,
    path: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    seg_wit: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddressResultJson {
    chain_type: String,
    path: String,
    address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyDerivationJson {
    chain_type: String,
    curve: String,
    path: String,
    #[serde(default)]
    network: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeysParamJson {
    derivations: Vec<PublicKeyDerivationJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeysResultJson {
    public_keys: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtendedPublicKeysResultJson {
    extended_public_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveAccountsParamJson {
    derivations: Vec<DerivationJson>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DerivationJson {
    chain_type: String,
    path: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    seg_wit: String,
    curve: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveSubAccountsParamJson {
    chain_type: String,
    curve: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    seg_wit: String,
    relative_paths: Vec<String>,
    extended_public_key: String,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct AccountResponseJson {
    chain_type: String,
    address: String,
    path: String,
    curve: String,
    public_key: String,
    extended_public_key: String,
    encrypted_extended_public_key: String,
    seg_wit: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeriveAccountsResultJson {
    accounts: Vec<AccountResponseJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalAddressResultJson {
    address: String,
    derived_path: String,
    #[serde(rename = "type")]
    address_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalAddressParamJson {
    path: String,
    chain_type: String,
    network: String,
    #[serde(default)]
    seg_wit: String,
    external_idx: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignParamJson {
    chain_type: String,
    path: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    payment: String,
    #[serde(default)]
    receiver: String,
    #[serde(default)]
    sender: String,
    #[serde(default)]
    fee: String,
    #[serde(default)]
    seg_wit: String,
    input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthAccessListJson {
    address: String,
    #[serde(default)]
    storage_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthTxInputJson {
    nonce: String,
    #[serde(default)]
    gas_price: String,
    gas_limit: String,
    to: String,
    value: String,
    #[serde(default)]
    data: String,
    chain_id: String,
    #[serde(default, rename = "type", alias = "txType")]
    tx_type: String,
    #[serde(default)]
    max_fee_per_gas: String,
    #[serde(default)]
    max_priority_fee_per_gas: String,
    #[serde(default)]
    access_list: Vec<EthAccessListJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthMessageInputJson {
    message: String,
    #[serde(default)]
    is_personal_sign: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TronTxInputJson {
    raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TronMessageInputJson {
    message: String,
    #[serde(default = "default_tron_header")]
    header: String,
    #[serde(default)]
    version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosmosTxInputJson {
    #[serde(alias = "signData")]
    data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TezosTxInputJson {
    raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubstrateTxInputJson {
    raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EosTxInputJson {
    transactions: Vec<EosSignDataJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EosSignDataJson {
    tx_hex: String,
    #[serde(default)]
    public_keys: Vec<String>,
    chain_id: String,
    receiver: String,
    payment: String,
    #[serde(default)]
    sender: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EosMessageInputJson {
    data: String,
    pubkey: String,
    #[serde(default)]
    is_hex: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcUtxoJson {
    #[serde(alias = "txHash")]
    tx_hash: String,
    vout: u32,
    amount: u64,
    address: String,
    #[serde(alias = "scriptPubKey")]
    script_pub_key: String,
    #[serde(alias = "derivedPath")]
    derived_path: String,
    #[serde(default)]
    sequence: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcTxExtraJson {
    #[serde(default)]
    op_return: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcTxInputJson {
    to: String,
    amount: u64,
    fee: u64,
    change_address_index: Option<u32>,
    #[serde(default)]
    change_address: String,
    #[serde(default)]
    unspents: Vec<BtcUtxoJson>,
    #[serde(default)]
    seg_wit: String,
    #[serde(default)]
    extra: Option<BtcTxExtraJson>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FilecoinTxInputJson {
    to: String,
    from: String,
    nonce: u64,
    value: String,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
    method: u64,
    #[serde(default)]
    params: String,
}

impl From<FilecoinTxInputJson> for FilecoinTxInput {
    fn from(input: FilecoinTxInputJson) -> Self {
        Self {
            to: input.to,
            from: input.from,
            nonce: input.nonce,
            value: input.value,
            gas_limit: input.gas_limit,
            gas_fee_cap: input.gas_fee_cap,
            gas_premium: input.gas_premium,
            method: input.method,
            params: input.params,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbOutPointJson {
    tx_hash: String,
    index: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbWitnessJson {
    #[serde(default)]
    lock: String,
    #[serde(default)]
    input_type: String,
    #[serde(default)]
    output_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbScriptJson {
    args: String,
    code_hash: String,
    hash_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbCellInputJson {
    previous_output: Option<CkbOutPointJson>,
    #[serde(default)]
    since: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbCachedCellJson {
    #[serde(default)]
    capacity: i64,
    lock: Option<CkbScriptJson>,
    out_point: Option<CkbOutPointJson>,
    derived_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CkbTxInputJson {
    inputs: Vec<CkbCellInputJson>,
    witnesses: Vec<CkbWitnessJson>,
    cached_cells: Vec<CkbCachedCellJson>,
    tx_hash: String,
}

impl From<CkbOutPointJson> for CkbOutPoint {
    fn from(value: CkbOutPointJson) -> Self {
        Self {
            tx_hash: value.tx_hash,
            index: value.index,
        }
    }
}

impl From<CkbTxInputJson> for CkbTxInput {
    fn from(input: CkbTxInputJson) -> Self {
        Self {
            inputs: input
                .inputs
                .into_iter()
                .map(|value| CkbCellInput {
                    previous_output: value.previous_output.map(Into::into),
                    since: value.since,
                })
                .collect(),
            witnesses: input
                .witnesses
                .into_iter()
                .map(|value| CkbWitness {
                    lock: value.lock,
                    input_type: value.input_type,
                    output_type: value.output_type,
                })
                .collect(),
            cached_cells: input
                .cached_cells
                .into_iter()
                .map(|value| CkbCachedCell {
                    capacity: value.capacity,
                    lock: value.lock.map(|script| CkbScript {
                        args: script.args,
                        code_hash: script.code_hash,
                        hash_type: script.hash_type,
                    }),
                    out_point: value.out_point.map(Into::into),
                    derived_path: value.derived_path,
                })
                .collect(),
            tx_hash: input.tx_hash,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcMessageInputJson {
    message: String,
    #[serde(default)]
    signature_type: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PsbtInputJson {
    psbt: String,
    #[serde(default)]
    auto_finalize: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EthTxOutputJson {
    signature: String,
    tx_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageOutputJson {
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TezosTxOutputJson {
    signature: String,
    edsig: String,
    sbytes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EosTxOutputJson {
    trans_multi_signs: Vec<EosSignResultJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EosSignResultJson {
    hash: String,
    signs: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BtcTxOutputJson {
    signature: String,
    tx_hash: String,
    wtx_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PsbtOutputJson {
    psbt: String,
}

fn default_tron_header() -> String {
    "TRON".to_string()
}

fn parse_bitcoin_network(value: &str) -> Result<Network, JsValue> {
    match value.to_ascii_uppercase().as_str() {
        "MAINNET" | "BITCOIN" => Ok(Network::Bitcoin),
        "TESTNET" => Ok(Network::Testnet),
        "REGTEST" => Ok(Network::Regtest),
        "SIGNET" => Ok(Network::Signet),
        _ => Err(js_err("missing_network")),
    }
}

fn parse_btc_signature_type(value: serde_json::Value) -> Result<i32, JsValue> {
    if value.is_null() {
        return Ok(BtcSignatureType::Standard as i32);
    }
    if let Some(number) = value.as_i64() {
        return i32::try_from(number).map_err(|_| js_err("invalid_signature_type"));
    }
    let text = value
        .as_str()
        .ok_or_else(|| js_err("invalid_signature_type"))?;
    match text.to_ascii_uppercase().as_str() {
        "STANDARD" => Ok(BtcSignatureType::Standard as i32),
        "BIP137" => Ok(BtcSignatureType::Bip137 as i32),
        "BIP322" => Ok(BtcSignatureType::Bip322 as i32),
        _ => Err(js_err("invalid_signature_type")),
    }
}

fn public_key_prefix(public_key: &str) -> Result<&str, JsValue> {
    public_key
        .get(..130)
        .ok_or_else(|| js_err("invalid_public_key"))
}

fn sign_param_from_json(params: &SignParamJson) -> SignParam {
    SignParam {
        chain_type: params.chain_type.clone(),
        path: params.path.clone(),
        network: params.network.clone(),
        input: None,
        payment: params.payment.clone(),
        receiver: params.receiver.clone(),
        sender: params.sender.clone(),
        fee: params.fee.clone(),
        seg_wit: params.seg_wit.clone(),
    }
}

fn parse_eth_argument(value: &str) -> Result<U256, JsValue> {
    if value.to_lowercase().starts_with("0x") {
        U256::from_str(&value[2..]).map_err(|_| js_err("unpack eth argument error"))
    } else {
        U256::from_dec_str(value).map_err(|_| js_err("unpack eth argument dec error"))
    }
}

fn remove_0x(value: &str) -> &str {
    if value.to_lowercase().starts_with("0x") {
        &value[2..]
    } else {
        value
    }
}

fn parse_eth_chain_id(value: &str) -> Result<u64, JsValue> {
    match value.parse::<u64>() {
        Ok(id) => Ok(id),
        Err(_) => {
            if value.to_lowercase().starts_with("0x") {
                u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| js_err("unpack eth argument error"))
            } else {
                u64::from_str_radix(value, 16).map_err(|_| js_err("unpack eth argument error"))
            }
        }
    }
}

fn eth_transaction_from_json(input: EthTxInputJson) -> Result<(EthTransaction, u64), JsValue> {
    let data_vec = if input.data.is_empty() {
        Vec::new()
    } else if input.data.starts_with("0x") {
        hex::decode(&input.data[2..]).map_err(|_| js_err("imkey_illegal_param"))?
    } else {
        hex::decode(&input.data).map_err(|_| js_err("imkey_illegal_param"))?
    };

    let to = if input.to.is_empty() || input.to == "0x" {
        "0000000000000000000000000000000000000000"
    } else {
        remove_0x(&input.to)
    };

    let is_eip1559 = input.tx_type.to_lowercase() == "0x02"
        || input.tx_type.to_lowercase() == "0x2"
        || input.tx_type == ikc_common::constants::ETH_TRANSACTION_TYPE_EIP1559;
    let chain_id = parse_eth_chain_id(&input.chain_id)?;

    let tx = if is_eip1559 {
        EthTransaction {
            nonce: parse_eth_argument(&input.nonce)?,
            gas_price: U256::from(0),
            gas_limit: parse_eth_argument(&input.gas_limit)?,
            to: EthAction::Call(
                EthRawAddress::from_str(to).map_err(|_| js_err("invalid_address"))?,
            ),
            value: parse_eth_argument(&input.value)?,
            data: data_vec,
            tx_type: ikc_common::constants::ETH_TRANSACTION_TYPE_EIP1559.to_string(),
            max_fee_per_gas: Some(parse_eth_argument(&input.max_fee_per_gas)?),
            max_priority_fee_per_gas: Some(parse_eth_argument(&input.max_priority_fee_per_gas)?),
            access_list: input
                .access_list
                .into_iter()
                .map(|item| {
                    Ok(AccessListItem {
                        address: EthRawAddress::from_str(remove_0x(&item.address))
                            .map_err(|_| js_err("invalid_address"))?,
                        storage_keys: item
                            .storage_keys
                            .into_iter()
                            .map(|key| {
                                Ok(EthTransaction::hexstring_to_hex256(remove_0x(&key)))
                                    as Result<H256, JsValue>
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    })
                })
                .collect::<Result<Vec<_>, JsValue>>()?,
        }
    } else {
        EthTransaction {
            nonce: parse_eth_argument(&input.nonce)?,
            gas_price: parse_eth_argument(&input.gas_price)?,
            gas_limit: parse_eth_argument(&input.gas_limit)?,
            to: EthAction::Call(
                EthRawAddress::from_str(to).map_err(|_| js_err("invalid_address"))?,
            ),
            value: parse_eth_argument(&input.value)?,
            data: data_vec,
            tx_type: input.tx_type,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        }
    };

    Ok((tx, chain_id))
}

fn with_encrypted_xpub(
    account: &mut AccountResponseJson,
    ext_public_key: String,
    network: &str,
) -> Result<(), JsValue> {
    if ext_public_key.is_empty() {
        return Ok(());
    }
    let extended_pub_key = Xpub::from_str(&ext_public_key).map_err(|_| js_err("invalid_xpub"))?;
    let ext_version = get_xpub_prefix(network);
    let ext_public_key = to_ss58check_with_version(extended_pub_key, &ext_version);
    account.extended_public_key = ext_public_key.clone();
    account.encrypted_extended_public_key = encrypt_xpub(&ext_public_key).map_err(map_err)?;
    Ok(())
}

async fn derive_one_account(derivation: DerivationJson) -> Result<AccountResponseJson, JsValue> {
    let chain_type = derivation.chain_type.to_ascii_uppercase();
    let account_path = if derivation.curve.eq_ignore_ascii_case("secp256k1") {
        get_account_path(&derivation.path).map_err(|err| js_err(err.to_string()))?
    } else {
        String::new()
    };
    let mut account = AccountResponseJson {
        chain_type: derivation.chain_type.clone(),
        path: derivation.path.clone(),
        curve: derivation.curve.clone(),
        seg_wit: derivation.seg_wit.clone(),
        ..Default::default()
    };

    let ext_public_key = match chain_type.as_str() {
        "BITCOIN" | "DOGECOIN" => {
            let network = BtcKinNetwork::find_by_coin(&derivation.chain_type, &derivation.network)
                .ok_or_else(|| js_err("missing_network"))?;
            let public_key = BtcKinAddress::get_pub_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = format!("0x{}", uncompress_pubkey_2_compress(&public_key));
            let address = match derivation.seg_wit.as_str() {
                "P2WPKH" => {
                    BtcKinAddress::p2shwpkh_async(&js_transport(), network, &derivation.path).await
                }
                "VERSION_0" => {
                    BtcKinAddress::p2wpkh_async(&js_transport(), network, &derivation.path).await
                }
                "VERSION_1" => {
                    BtcKinAddress::p2tr_async(&js_transport(), network, &derivation.path).await
                }
                _ => BtcKinAddress::p2pkh_async(&js_transport(), network, &derivation.path).await,
            }
            .map_err(map_err)?;
            account.address = address.to_string();
            BtcKinAddress::get_xpub_async(
                &js_transport(),
                ikc_common::utility::network_convert(&derivation.network),
                &account_path,
            )
            .await
            .map_err(map_err)?
        }
        "LITECOIN" => {
            let public_key = BtcForkAddress::get_pub_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = public_key;
            let network = network_from_param(
                &derivation.chain_type,
                &derivation.network,
                &derivation.seg_wit,
            )
            .or_else(|| network_from_param(&derivation.chain_type, &derivation.network, "NONE"))
            .ok_or_else(|| js_err("missing_network"))?;
            account.address = match derivation.seg_wit.as_str() {
                "P2WPKH" => {
                    BtcForkAddress::p2shwpkh_async(&js_transport(), &network, &derivation.path)
                        .await
                }
                "SEGWIT" | "VERSION_0" => {
                    BtcForkAddress::p2wpkh_async(&js_transport(), &network, &derivation.path).await
                }
                _ => BtcForkAddress::p2pkh_async(&js_transport(), &network, &derivation.path).await,
            }
            .map_err(map_err)?;
            BtcForkAddress::get_xpub_async(
                &js_transport(),
                ikc_common::utility::network_convert(&derivation.network),
                &account_path,
            )
            .await
            .map_err(map_err)?
        }
        "BITCOINCASH" => {
            let network = ikc_common::utility::network_convert(&derivation.network);
            let public_key =
                BchAddress::get_pub_key_async(&js_transport(), network, &derivation.path)
                    .await
                    .map_err(map_err)?;
            account.public_key = format!("0x{}", uncompress_pubkey_2_compress(&public_key));
            account.address =
                BchAddress::get_address_async(&js_transport(), network, &derivation.path)
                    .await
                    .map_err(map_err)?;
            BtcAddress::get_xpub_async(&js_transport(), network, &account_path)
                .await
                .map_err(map_err)?
        }
        "ETHEREUM" => {
            let public_key = EthAddress::get_pub_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = format!(
                "0x{}",
                uncompress_pubkey_2_compress(public_key_prefix(&public_key)?)
            );
            account.address = EthAddress::get_address_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            EthAddress::get_xpub_async(&js_transport(), &account_path)
                .await
                .map_err(map_err)?
        }
        "COSMOS" => {
            let public_key = CosmosAddress::get_pub_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = format!(
                "0x{}",
                uncompress_pubkey_2_compress(public_key_prefix(&public_key)?)
            );
            account.address = CosmosAddress::get_address_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            CosmosAddress::get_xpub_async(&js_transport(), &account_path)
                .await
                .map_err(map_err)?
        }
        "TRON" => {
            let public_key = hex::encode(
                TronAddress::get_pub_key_async(&js_transport(), &derivation.path)
                    .await
                    .map_err(map_err)?,
            );
            account.public_key = format!(
                "0x{}",
                uncompress_pubkey_2_compress(public_key_prefix(&public_key)?)
            );
            account.address = TronAddress::get_address_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            TronAddress::get_xpub_async(&js_transport(), &account_path)
                .await
                .map_err(map_err)?
        }
        "POLKADOT" | "KUSAMA" => {
            let address_type = derivation
                .chain_type
                .parse::<SubstrateAddressType>()
                .map_err(map_err)?;
            let public_key = SubstrateAddress::get_public_key_async(
                &js_transport(),
                &derivation.path,
                &address_type,
            )
            .await
            .map_err(map_err)?;
            account.public_key = format!("0x{}", public_key).to_lowercase();
            account.address = SubstrateAddress::get_address_async(
                &js_transport(),
                &derivation.path,
                &address_type,
            )
            .await
            .map_err(map_err)?;
            String::new()
        }
        "EOS" => {
            account.public_key = EosPubkey::get_pubkey_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.address = String::new();
            EosPubkey::get_xpub_async(&js_transport(), &account_path)
                .await
                .map_err(map_err)?
        }
        "FILECOIN" => {
            let public_key = FilecoinAddress::get_pub_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = format!(
                "0x{}",
                uncompress_pubkey_2_compress(public_key_prefix(&public_key)?)
            );
            account.address = FilecoinAddress::get_address_async(
                &js_transport(),
                &derivation.path,
                &derivation.network,
            )
            .await
            .map_err(map_err)?;
            FilecoinAddress::get_xpub_async(&js_transport(), &derivation.network, &account_path)
                .await
                .map_err(map_err)?
        }
        "NERVOS" => {
            let public_key = CkbAddress::get_public_key_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err)?;
            account.public_key = format!(
                "0x{}",
                uncompress_pubkey_2_compress(public_key_prefix(&public_key)?)
            );
            account.address = CkbAddress::get_address_async(
                &js_transport(),
                &derivation.network,
                &derivation.path,
            )
            .await
            .map_err(map_err)?;
            CkbAddress::get_xpub_async(&js_transport(), &derivation.network, &account_path)
                .await
                .map_err(map_err)?
        }
        _ => return Err(js_err("unsupported_chain_type")),
    };

    with_encrypted_xpub(&mut account, ext_public_key, &derivation.network)?;
    Ok(account)
}

fn derive_sub_account_address(
    chain_type: &str,
    network: &str,
    seg_wit: &str,
    pub_key_uncompressed: Vec<u8>,
) -> Result<String, JsValue> {
    match chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" => EthAddress::from_pub_key(pub_key_uncompressed).map_err(map_err),
        "BITCOIN" | "DOGECOIN" => {
            let network = BtcKinNetwork::find_by_coin(chain_type, network)
                .ok_or_else(|| js_err("missing_network"))?;
            BtcKinAddress::from_public_key(&hex::encode(pub_key_uncompressed), network, seg_wit)
                .map(|address| address.to_string())
                .map_err(map_err)
        }
        "LITECOIN" => {
            let network = network_from_param(chain_type, network, seg_wit)
                .or_else(|| network_from_param(chain_type, network, "NONE"))
                .ok_or_else(|| js_err("missing_network"))?;
            BtcForkAddress::from_pub_key(pub_key_uncompressed, network).map_err(map_err)
        }
        "COSMOS" => CosmosAddress::from_pub_key(pub_key_uncompressed).map_err(map_err),
        "TRON" => TronAddress::from_pub_key(&pub_key_uncompressed).map_err(map_err),
        "EOS" => EosPubkey::from_pub_key(&pub_key_uncompressed).map_err(map_err),
        "BITCOINCASH" => BchAddress::from_pub_key(&pub_key_uncompressed, network).map_err(map_err),
        "FILECOIN" => FilecoinAddress::from_pub_key(pub_key_uncompressed, network).map_err(map_err),
        "NERVOS" => {
            let compressed = uncompress_pubkey_2_compress(&hex::encode(pub_key_uncompressed));
            let compressed = hex::decode(compressed).map_err(|err| js_err(err.to_string()))?;
            CkbAddress::from_public_key(network, &compressed).map_err(map_err)
        }
        _ => Err(js_err("unsupported_chain_type")),
    }
}

async fn get_chain_address(params: &AddressParamJson, display: bool) -> Result<String, JsValue> {
    match params.chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" => {
            if display {
                EthAddress::display_address_async(&js_transport(), &params.path).await
            } else {
                EthAddress::get_address_async(&js_transport(), &params.path).await
            }
        }
        "COSMOS" => {
            if display {
                CosmosAddress::display_address_async(&js_transport(), &params.path).await
            } else {
                CosmosAddress::get_address_async(&js_transport(), &params.path).await
            }
        }
        "BITCOIN" | "DOGECOIN" => {
            let network = BtcKinNetwork::find_by_coin(&params.chain_type, &params.network)
                .ok_or_else(|| js_err("missing_network"))?;
            if display {
                BtcKinAddress::display_address_async(
                    &js_transport(),
                    network,
                    &params.path,
                    &params.seg_wit,
                )
                .await
            } else {
                let path = format!("{}/0/0", params.path);
                let address = match params.seg_wit.as_str() {
                    "P2WPKH" => {
                        BtcKinAddress::p2shwpkh_async(&js_transport(), network, &path).await
                    }
                    "VERSION_0" => {
                        BtcKinAddress::p2wpkh_async(&js_transport(), network, &path).await
                    }
                    "VERSION_1" => BtcKinAddress::p2tr_async(&js_transport(), network, &path).await,
                    _ => BtcKinAddress::p2pkh_async(&js_transport(), network, &path).await,
                };
                address.map(|address| address.to_string())
            }
        }
        "LITECOIN" => {
            let network = network_from_param(&params.chain_type, &params.network, &params.seg_wit)
                .or_else(|| network_from_param(&params.chain_type, &params.network, "NONE"))
                .ok_or_else(|| js_err("missing_network"))?;
            if display {
                BtcForkAddress::display_address_async(&js_transport(), &network, &params.path).await
            } else {
                match params.seg_wit.as_str() {
                    "P2WPKH" => {
                        BtcForkAddress::p2shwpkh_async(&js_transport(), &network, &params.path)
                            .await
                    }
                    "SEGWIT" | "VERSION_0" => {
                        BtcForkAddress::p2wpkh_async(&js_transport(), &network, &params.path).await
                    }
                    _ => BtcForkAddress::p2pkh_async(&js_transport(), &network, &params.path).await,
                }
            }
        }
        "BITCOINCASH" => {
            let network = ikc_common::utility::network_convert(&params.network);
            if display {
                BchAddress::display_address_async(&js_transport(), network, &params.path).await
            } else {
                BchAddress::get_address_async(&js_transport(), network, &params.path).await
            }
        }
        "FILECOIN" => {
            if display {
                FilecoinAddress::display_address_async(
                    &js_transport(),
                    &params.path,
                    &params.network,
                )
                .await
            } else {
                FilecoinAddress::get_address_async(&js_transport(), &params.path, &params.network)
                    .await
            }
        }
        "TRON" => {
            if display {
                TronAddress::display_address_async(&js_transport(), &params.path).await
            } else {
                TronAddress::get_address_async(&js_transport(), &params.path).await
            }
        }
        "POLKADOT" | "KUSAMA" => {
            let address_type = params
                .chain_type
                .parse::<SubstrateAddressType>()
                .map_err(map_err)?;
            if display {
                SubstrateAddress::display_address_async(
                    &js_transport(),
                    &params.path,
                    &address_type,
                )
                .await
            } else {
                SubstrateAddress::get_address_async(&js_transport(), &params.path, &address_type)
                    .await
            }
        }
        "TEZOS" => {
            if display {
                TezosAddress::display_address_async(&js_transport(), &params.path).await
            } else {
                TezosAddress::get_address_async(&js_transport(), &params.path).await
            }
        }
        "NERVOS" => {
            if display {
                CkbAddress::display_address_async(&js_transport(), &params.network, &params.path)
                    .await
            } else {
                CkbAddress::get_address_async(&js_transport(), &params.network, &params.path).await
            }
        }
        _ => return Err(js_err("unsupported_chain_type")),
    }
    .map_err(map_err)
}

async fn get_chain_public_key(derivation: &PublicKeyDerivationJson) -> Result<String, JsValue> {
    let public_key = match derivation.chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" | "COSMOS" | "TRON" | "BITCOIN" | "DOGECOIN" | "LITECOIN" | "BITCOINCASH"
        | "FILECOIN" | "NERVOS" => {
            if !derivation.curve.eq_ignore_ascii_case("secp256k1") {
                return Err(js_err("unsupported_curve_type"));
            }
            match derivation.chain_type.to_ascii_uppercase().as_str() {
                "ETHEREUM" => EthAddress::get_pub_key_async(&js_transport(), &derivation.path)
                    .await
                    .map_err(map_err)?,
                "COSMOS" => CosmosAddress::get_pub_key_async(&js_transport(), &derivation.path)
                    .await
                    .map_err(map_err)?,
                "TRON" => hex::encode(
                    TronAddress::get_pub_key_async(&js_transport(), &derivation.path)
                        .await
                        .map_err(map_err)?,
                ),
                "BITCOIN" | "DOGECOIN" => {
                    BtcKinAddress::get_pub_key_async(&js_transport(), &derivation.path)
                        .await
                        .map_err(map_err)?
                }
                "LITECOIN" => {
                    let public_key =
                        BtcForkAddress::get_pub_key_async(&js_transport(), &derivation.path)
                            .await
                            .map_err(map_err)?;
                    return Ok(public_key);
                }
                "BITCOINCASH" => {
                    let public_key = BchAddress::get_pub_key_async(
                        &js_transport(),
                        Network::Bitcoin,
                        &derivation.path,
                    )
                    .await
                    .map_err(map_err)?;
                    public_key
                }
                "FILECOIN" => FilecoinAddress::get_pub_key_async(&js_transport(), &derivation.path)
                    .await
                    .map_err(map_err)?,
                "NERVOS" => CkbAddress::get_public_key_async(&js_transport(), &derivation.path)
                    .await
                    .map_err(map_err)?,
                _ => unreachable!(),
            }
        }
        "POLKADOT" | "KUSAMA" => {
            if !derivation.curve.eq_ignore_ascii_case("ed25519") {
                return Err(js_err("unsupported_curve_type"));
            }
            let address_type = derivation
                .chain_type
                .parse::<SubstrateAddressType>()
                .map_err(map_err)?;
            let public_key = SubstrateAddress::get_public_key_async(
                &js_transport(),
                &derivation.path,
                &address_type,
            )
            .await
            .map_err(map_err)?;
            return Ok(format!("0x{}", public_key));
        }
        "EOS" => {
            if !derivation.curve.eq_ignore_ascii_case("secp256k1") {
                return Err(js_err("unsupported_curve_type"));
            }
            return EosPubkey::get_pubkey_async(&js_transport(), &derivation.path)
                .await
                .map_err(map_err);
        }
        _ => return Err(js_err("unsupported_chain_type")),
    };
    let public_key = public_key_prefix(&public_key)?;
    Ok(format!("0x{}", uncompress_pubkey_2_compress(public_key)))
}

async fn get_chain_xpub(derivation: &PublicKeyDerivationJson) -> Result<String, JsValue> {
    if !derivation.curve.eq_ignore_ascii_case("secp256k1") {
        return Err(js_err("unsupported_curve_type"));
    }
    let network = if derivation.network.is_empty() {
        "MAINNET"
    } else {
        derivation.network.as_str()
    };

    match derivation.chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" => EthAddress::get_xpub_async(&js_transport(), &derivation.path).await,
        "BITCOIN" | "DOGECOIN" => {
            BtcKinAddress::get_xpub_async(&js_transport(), Network::Bitcoin, &derivation.path).await
        }
        "LITECOIN" => {
            BtcForkAddress::get_xpub_async(&js_transport(), Network::Bitcoin, &derivation.path)
                .await
        }
        "BITCOINCASH" => {
            coin_bitcoin::address::BtcAddress::get_xpub_async(
                &js_transport(),
                Network::Bitcoin,
                &derivation.path,
            )
            .await
        }
        "COSMOS" => CosmosAddress::get_xpub_async(&js_transport(), &derivation.path).await,
        "FILECOIN" => {
            FilecoinAddress::get_xpub_async(&js_transport(), network, &derivation.path).await
        }
        "TRON" => TronAddress::get_xpub_async(&js_transport(), &derivation.path).await,
        "EOS" => EosPubkey::get_xpub_async(&js_transport(), &derivation.path).await,
        "NERVOS" => CkbAddress::get_xpub_async(&js_transport(), network, &derivation.path).await,
        _ => return Err(js_err("unsupported_chain_type")),
    }
    .map_err(map_err)
}

struct JsBindingStorage;

impl AsyncBindingStorage for JsBindingStorage {
    fn load<'a>(&'a self, seid: &'a str) -> BoxFutureResult<'a, Option<String>> {
        Box::pin(async move {
            let storage = binding_storage()
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let method = Reflect::get(&storage, &JsValue::from_str("getBindKey"))
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let method = method
                .dyn_ref::<Function>()
                .ok_or_else(|| anyhow::anyhow!("storage.getBindKey is not a function"))?;
            let promise = method
                .call1(&storage, &JsValue::from_str(seid))
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let promise = promise
                .dyn_into::<Promise>()
                .map_err(|_| anyhow::anyhow!("storage.getBindKey must return a Promise"))?;
            let value = JsFuture::from(promise)
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;

            if value.is_null() || value.is_undefined() {
                Ok(None)
            } else {
                value.as_string().map(Some).ok_or_else(|| {
                    anyhow::anyhow!("storage.getBindKey must resolve a string or null")
                })
            }
        })
    }

    fn save<'a>(&'a self, seid: &'a str, encrypted_key: &'a str) -> BoxFutureResult<'a, ()> {
        Box::pin(async move {
            let storage = binding_storage()
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let method = Reflect::get(&storage, &JsValue::from_str("setBindKey"))
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let method = method
                .dyn_ref::<Function>()
                .ok_or_else(|| anyhow::anyhow!("storage.setBindKey is not a function"))?;
            let promise = method
                .call2(
                    &storage,
                    &JsValue::from_str(seid),
                    &JsValue::from_str(encrypted_key),
                )
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            let promise = promise
                .dyn_into::<Promise>()
                .map_err(|_| anyhow::anyhow!("storage.setBindKey must return a Promise"))?;
            JsFuture::from(promise)
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_storage_error")))?;
            Ok(())
        })
    }
}

fn js_transport() -> JsApduTransport {
    JsApduTransport {
        profile: transport_profile(),
    }
}

#[wasm_bindgen]
pub fn set_transport(transport: JsValue) {
    TRANSPORT.with(|slot| {
        *slot.borrow_mut() = Some(transport);
    });
}

#[wasm_bindgen]
pub fn set_transport_profile(profile: &str) -> Result<(), JsValue> {
    let profile = parse_transport_profile(profile)?;
    TRANSPORT_PROFILE.with(|slot| {
        *slot.borrow_mut() = profile;
    });
    Ok(())
}

#[wasm_bindgen]
pub fn configure_tsm(base_url: &str) -> Result<String, JsValue> {
    ikc_common::tsm::configure_tsm_url(base_url).map_err(map_err)?;
    Ok(ikc_common::tsm::tsm_base_url())
}

#[wasm_bindgen]
pub fn set_tsm_client(client: JsValue) {
    TSM_CLIENT.with(|slot| {
        *slot.borrow_mut() = Some(client);
    });
}

#[wasm_bindgen]
pub fn set_binding_storage(storage: JsValue) {
    BINDING_STORAGE.with(|slot| {
        *slot.borrow_mut() = Some(storage);
    });
}

#[wasm_bindgen]
pub fn clear_transport() {
    TRANSPORT.with(|slot| {
        *slot.borrow_mut() = None;
    });
    TRANSPORT_PROFILE.with(|slot| {
        *slot.borrow_mut() = TransportProfile::WebUsb;
    });
}

#[wasm_bindgen]
pub fn clear_tsm_client() {
    TSM_CLIENT.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[wasm_bindgen]
pub fn clear_binding_storage() {
    BINDING_STORAGE.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[wasm_bindgen]
pub async fn send_apdu(apdu_hex: &str, timeout_ms: Option<u32>) -> Result<String, JsValue> {
    let response = call_transport(&normalize_hex(apdu_hex), timeout_ms).await?;
    ikc_common::apdu::ApduCheck::check_response(&response).map_err(map_err)?;
    Ok(response)
}

#[wasm_bindgen]
pub async fn send_apdu_unchecked(
    apdu_hex: &str,
    timeout_ms: Option<u32>,
) -> Result<String, JsValue> {
    call_transport(&normalize_hex(apdu_hex), timeout_ms).await
}

#[wasm_bindgen]
pub async fn tsm_post(action: &str, body_json: &str) -> Result<String, JsValue> {
    call_tsm(action, body_json).await
}

#[wasm_bindgen]
pub async fn get_seid() -> Result<String, JsValue> {
    async_device_manager::get_se_id(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_sn() -> Result<String, JsValue> {
    async_device_manager::get_sn(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_ram_size() -> Result<String, JsValue> {
    async_device_manager::get_ram_size(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_firmware_version() -> Result<String, JsValue> {
    async_device_manager::get_firmware_version(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub fn get_sdk_info() -> String {
    async_device_manager::get_sdk_info()
}

#[wasm_bindgen]
pub async fn get_battery_power() -> Result<String, JsValue> {
    async_device_manager::get_battery_power(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_ble_name() -> Result<String, JsValue> {
    async_device_manager::get_ble_name(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn set_ble_name(ble_name: &str) -> Result<String, JsValue> {
    async_device_manager::set_ble_name(&js_transport(), ble_name)
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_ble_version() -> Result<String, JsValue> {
    async_device_manager::get_ble_version(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_life_time() -> Result<String, JsValue> {
    async_device_manager::get_life_time(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_cert() -> Result<String, JsValue> {
    async_device_manager::get_cert(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn bind_display_code() -> Result<(), JsValue> {
    async_device_manager::bind_display_code(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn bind_check() -> Result<String, JsValue> {
    async_device_manager::bind_check(&js_transport(), &JsTsmClient, &JsBindingStorage)
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn bind_acquire(binding_code: &str) -> Result<String, JsValue> {
    async_device_manager::bind_acquire(&js_transport(), &JsTsmClient, binding_code)
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn secure_check() -> Result<String, JsValue> {
    async_device_manager::secure_check(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn activate_device() -> Result<String, JsValue> {
    async_device_manager::activate(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn check_update() -> Result<String, JsValue> {
    let response = async_device_manager::check_update(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_check_update_error"))
}

#[wasm_bindgen]
pub async fn app_download(app_name: &str) -> Result<String, JsValue> {
    let response = async_device_manager::app_download(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_app_download_error"))
}

#[wasm_bindgen]
pub async fn app_update(app_name: &str) -> Result<String, JsValue> {
    let response = async_device_manager::app_update(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_app_update_error"))
}

#[wasm_bindgen]
pub async fn app_delete(app_name: &str) -> Result<String, JsValue> {
    async_device_manager::app_delete(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn get_device_info() -> Result<String, JsValue> {
    let info = async_device_manager::get_device_info(&js_transport())
        .await
        .map_err(map_err)?;
    serde_json::to_string(&info).map_err(|_| js_err("serialize_device_info_error"))
}

#[wasm_bindgen]
pub async fn get_address(params_json: &str) -> Result<String, JsValue> {
    let params: AddressParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let address = get_chain_address(&params, false).await?;
    serde_json::to_string(&AddressResultJson {
        chain_type: params.chain_type,
        path: params.path,
        address,
    })
    .map_err(|_| js_err("serialize_address_error"))
}

#[wasm_bindgen]
pub async fn register_address(params_json: &str) -> Result<String, JsValue> {
    let params: AddressParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let address = get_chain_address(&params, true).await?;
    serde_json::to_string(&AddressResultJson {
        chain_type: params.chain_type,
        path: params.path,
        address,
    })
    .map_err(|_| js_err("serialize_address_error"))
}

#[wasm_bindgen]
pub async fn register_pub_key(params_json: &str) -> Result<String, JsValue> {
    let params: AddressParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    if !params.chain_type.eq_ignore_ascii_case("EOS") {
        return Err(js_err("register_pub_key unsupported_chain"));
    }
    let public_key = EosPubkey::display_pubkey_async(&js_transport(), &params.path)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&AddressResultJson {
        chain_type: params.chain_type,
        path: params.path,
        address: public_key,
    })
    .map_err(|_| js_err("serialize_pub_key_error"))
}

#[wasm_bindgen]
pub async fn get_public_keys(params_json: &str) -> Result<String, JsValue> {
    let params: PublicKeysParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let mut public_keys = Vec::new();
    for derivation in params.derivations {
        public_keys.push(get_chain_public_key(&derivation).await?);
    }
    serde_json::to_string(&PublicKeysResultJson { public_keys })
        .map_err(|_| js_err("serialize_public_keys_error"))
}

#[wasm_bindgen]
pub async fn get_extended_public_keys(params_json: &str) -> Result<String, JsValue> {
    let params: PublicKeysParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let mut extended_public_keys = Vec::new();
    for derivation in params.derivations {
        extended_public_keys.push(get_chain_xpub(&derivation).await?);
    }
    serde_json::to_string(&ExtendedPublicKeysResultJson {
        extended_public_keys,
    })
    .map_err(|_| js_err("serialize_extended_public_keys_error"))
}

#[wasm_bindgen]
pub async fn derive_accounts(params_json: &str) -> Result<String, JsValue> {
    let params: DeriveAccountsParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let mut accounts = Vec::new();
    for derivation in params.derivations {
        accounts.push(derive_one_account(derivation).await?);
    }
    serde_json::to_string(&DeriveAccountsResultJson { accounts })
        .map_err(|_| js_err("serialize_derive_accounts_error"))
}

#[wasm_bindgen]
pub async fn derive_sub_accounts(params_json: &str) -> Result<String, JsValue> {
    let params: DeriveSubAccountsParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    if !params.curve.eq_ignore_ascii_case("secp256k1") {
        return Err(js_err("invalid_curve_type"));
    }
    let xpub = from_ss58check_with_version(&params.extended_public_key).map_err(map_err)?;
    let encrypted_extended_public_key =
        encrypt_xpub(&params.extended_public_key).map_err(map_err)?;
    let mut account = AccountResponseJson {
        chain_type: params.chain_type.clone(),
        curve: params.curve.clone(),
        extended_public_key: params.extended_public_key.clone(),
        encrypted_extended_public_key,
        seg_wit: params.seg_wit.clone(),
        ..Default::default()
    };
    let mut accounts = Vec::new();
    for relative_path in params.relative_paths {
        let ext_pub_key = extended_pub_key_derive(&xpub.0, &relative_path).map_err(map_err)?;
        let pub_key_uncompressed = ext_pub_key.public_key.serialize_uncompressed().to_vec();
        account.public_key = format!("0x{}", ext_pub_key.public_key.serialize().to_hex());
        account.path = relative_path;
        account.address = derive_sub_account_address(
            &params.chain_type,
            &params.network,
            &params.seg_wit,
            pub_key_uncompressed,
        )?;
        accounts.push(account.clone());
    }
    serde_json::to_string(&DeriveAccountsResultJson { accounts })
        .map_err(|_| js_err("serialize_derive_sub_accounts_error"))
}

#[wasm_bindgen]
pub async fn calc_external_address(params_json: &str) -> Result<String, JsValue> {
    let params: ExternalAddressParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    if !params.chain_type.eq_ignore_ascii_case("BITCOIN") {
        return Err(js_err("calc_external_address unsupported_chain"));
    }
    let network = ikc_common::utility::network_convert(&params.network);
    let external_path = format!("{}/0/{}", params.path, params.external_idx);
    let address = match params.seg_wit.as_str() {
        "P2WPKH" => BtcAddress::p2shwpkh_async(&js_transport(), network, &external_path).await,
        "VERSION_0" => BtcAddress::p2wpkh_async(&js_transport(), network, &external_path).await,
        "VERSION_1" => BtcAddress::p2tr_async(&js_transport(), network, &external_path).await,
        _ => BtcAddress::p2pkh_async(&js_transport(), network, &external_path).await,
    }
    .map_err(map_err)?;
    serde_json::to_string(&ExternalAddressResultJson {
        address,
        derived_path: format!("0/{}", params.external_idx),
        address_type: "EXTERNAL".to_string(),
    })
    .map_err(|_| js_err("serialize_external_address_error"))
}

#[wasm_bindgen]
pub async fn sign_tx(params_json: &str) -> Result<String, JsValue> {
    let params: SignParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let sign_param = sign_param_from_json(&params);
    match params.chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" => {
            let input: EthTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let (transaction, chain_id) = eth_transaction_from_json(input)?;
            let output = transaction
                .sign_async(
                    &js_transport(),
                    Some(chain_id),
                    &sign_param.path,
                    &sign_param.payment,
                    &sign_param.receiver,
                    &sign_param.sender,
                    &sign_param.fee,
                )
                .await
                .map_err(map_err)?;
            serde_json::to_string(&EthTxOutputJson {
                signature: output.signature,
                tx_hash: output.tx_hash,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "TRON" => {
            let input: TronTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = TronSigner::sign_transaction_async(
                &js_transport(),
                TronTxInput {
                    raw_data: input.raw_data,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "COSMOS" => {
            let input: CosmosTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = CosmosTransaction {
                sign_data: input.data,
                path: sign_param.path,
                payment_dis: sign_param.payment,
                to_dis: sign_param.receiver,
                fee_dis: sign_param.fee,
            }
            .sign_async(&js_transport())
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "TEZOS" => {
            let input: TezosTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = TezosTransaction::sign_tx_async(
                &js_transport(),
                TezosTxInput {
                    raw_data: input.raw_data,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&TezosTxOutputJson {
                signature: output.signature,
                edsig: output.edsig,
                sbytes: output.sbytes,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "POLKADOT" | "KUSAMA" => {
            let input: SubstrateTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = SubstrateTransaction::sign_transaction_async(
                &js_transport(),
                &SubstrateRawTxIn {
                    raw_data: input.raw_data,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "EOS" => {
            let input: EosTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = EosTransaction::sign_tx_async(
                &js_transport(),
                EosTxInput {
                    transactions: input
                        .transactions
                        .into_iter()
                        .map(|data| EosSignData {
                            tx_hex: data.tx_hex,
                            public_keys: data.public_keys,
                            chain_id: data.chain_id,
                            receiver: data.receiver,
                            payment: data.payment,
                            sender: data.sender,
                        })
                        .collect(),
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&EosTxOutputJson {
                trans_multi_signs: output
                    .trans_multi_signs
                    .into_iter()
                    .map(|result| EosSignResultJson {
                        hash: result.hash,
                        signs: result.signs,
                    })
                    .collect(),
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "BITCOIN" | "DOGECOIN" => {
            let input: BtcTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let seg_wit = if input.seg_wit.is_empty() {
                sign_param.seg_wit.clone()
            } else {
                input.seg_wit.clone()
            };
            let extra_op_return = input
                .extra
                .as_ref()
                .and_then(|extra| (!extra.op_return.is_empty()).then(|| extra.op_return.clone()));
            let transaction = BtcTransaction {
                to: input.to,
                amount: input.amount,
                unspents: input
                    .unspents
                    .into_iter()
                    .map(|utxo| BtcUtxo {
                        txhash: utxo.tx_hash,
                        vout: utxo.vout,
                        amount: utxo.amount,
                        address: utxo.address,
                        script_pubkey: utxo.script_pub_key,
                        derive_path: utxo.derived_path,
                        sequence: utxo.sequence,
                    })
                    .collect(),
                fee: input.fee,
                chain_type: sign_param.chain_type.clone(),
            };
            let output = transaction
                .sign_transaction_async(
                    &js_transport(),
                    &sign_param.network,
                    &sign_param.path,
                    input.change_address_index,
                    extra_op_return.as_deref(),
                    &seg_wit,
                )
                .await
                .map_err(map_err)?;
            serde_json::to_string(&BtcTxOutputJson {
                signature: output.signature,
                tx_hash: output.tx_hash,
                wtx_hash: output.wtx_id,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "LITECOIN" => {
            let input: BtcTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let seg_wit = if input.seg_wit.is_empty() {
                sign_param.seg_wit.clone()
            } else {
                input.seg_wit.clone()
            };
            let coin_info =
                coin_info_from_param(&sign_param.chain_type, &sign_param.network, &seg_wit, "")
                    .map_err(map_err)?;
            let tx_input = BtcForkTxInput {
                to: input.to,
                amount: input.amount,
                unspents: input
                    .unspents
                    .into_iter()
                    .map(|utxo| BtcForkUtxo {
                        tx_hash: utxo.tx_hash,
                        vout: utxo.vout,
                        amount: utxo.amount,
                        address: utxo.address,
                        script_pub_key: utxo.script_pub_key,
                        derived_path: utxo.derived_path,
                        sequence: utxo.sequence,
                    })
                    .collect(),
                fee: input.fee,
                change_address_index: input.change_address_index.unwrap_or_default(),
                change_address: input.change_address,
                seg_wit: seg_wit.clone(),
            };
            let transaction = BtcForkTransaction {
                tx_input,
                coin_info,
            };
            let network = if sign_param.network.eq_ignore_ascii_case("TESTNET") {
                Network::Testnet
            } else {
                Network::Bitcoin
            };
            let extra_data: Vec<u8> = vec![];
            let output = if seg_wit.eq_ignore_ascii_case("P2WPKH") {
                transaction
                    .sign_segwit_transaction_async(
                        &js_transport(),
                        network,
                        &sign_param.path,
                        &extra_data,
                    )
                    .await
            } else {
                transaction
                    .sign_transaction_async(&js_transport(), network, &sign_param.path, &extra_data)
                    .await
            }
            .map_err(map_err)?;
            serde_json::to_string(&BtcTxOutputJson {
                signature: output.signature,
                tx_hash: output.tx_hash,
                wtx_hash: output.wtx_id,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "BITCOINCASH" => {
            let input: BtcTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let unspents = input
                .unspents
                .into_iter()
                .map(|utxo| BchUtxo {
                    txhash: utxo.tx_hash,
                    vout: utxo.vout,
                    amount: utxo.amount,
                    address: utxo.address,
                    script_pubkey: utxo.script_pub_key,
                    derive_path: utxo.derived_path,
                    sequence: utxo.sequence,
                })
                .collect();
            let transaction = BchTransaction {
                to: input.to,
                amount: input.amount,
                unspents,
                fee: input.fee,
            };
            let network = if sign_param.network.eq_ignore_ascii_case("TESTNET") {
                Network::Testnet
            } else {
                Network::Bitcoin
            };
            let extra_data: Vec<u8> = vec![];
            let output = transaction
                .sign_transaction_async(
                    &js_transport(),
                    network,
                    &sign_param.path,
                    input.change_address_index.unwrap_or_default() as i32,
                    &input.change_address,
                    &extra_data,
                )
                .await
                .map_err(map_err)?;
            serde_json::to_string(&BtcTxOutputJson {
                signature: output.signature,
                tx_hash: output.tx_hash,
                wtx_hash: output.wtx_id,
            })
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "FILECOIN" => {
            let input: FilecoinTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = FilecoinTransaction::sign_tx_async(
                &js_transport(),
                input.clone().into(),
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            let signature = output
                .signature
                .ok_or_else(|| js_err("filecoin_signature_missing"))?;
            serde_json::to_string(&serde_json::json!({
                "cid": output.cid,
                "message": input,
                "signature": {
                    "type": signature.r#type,
                    "data": signature.data,
                },
            }))
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        "NERVOS" => {
            let input: CkbTxInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output =
                CkbSigner::sign_transaction_async(&js_transport(), &input.into(), &sign_param)
                    .await
                    .map_err(map_err)?;
            serde_json::to_string(&serde_json::json!({
                "txHash": output.tx_hash,
                "witnesses": output.witnesses,
            }))
            .map_err(|_| js_err("serialize_sign_tx_error"))
        }
        _ => Err(js_err("sign_tx unsupported_chain")),
    }
}

#[wasm_bindgen]
pub async fn sign_message(params_json: &str) -> Result<String, JsValue> {
    let params: SignParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    let sign_param = sign_param_from_json(&params);
    match params.chain_type.to_ascii_uppercase().as_str() {
        "ETHEREUM" => {
            let input: EthMessageInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = EthTransaction::sign_message_async(
                &js_transport(),
                EthMessageInput {
                    message: input.message,
                    is_personal_sign: input.is_personal_sign,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_message_error"))
        }
        "TRON" => {
            let input: TronMessageInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = TronSigner::sign_message_async(
                &js_transport(),
                TronMessageInput {
                    message: input.message,
                    header: input.header,
                    version: input.version,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_message_error"))
        }
        "EOS" => {
            let input: EosMessageInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = EosTransaction::sign_message_async(
                &js_transport(),
                EosMessageInput {
                    data: input.data,
                    pubkey: input.pubkey,
                    is_hex: input.is_hex,
                },
                &sign_param,
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_message_error"))
        }
        "BITCOIN" => {
            let input: BtcMessageInputJson = serde_json::from_value(params.input.clone())
                .map_err(|_| js_err("imkey_illegal_param"))?;
            let output = MessageSinger {
                derivation_path: sign_param.path,
                chain_type: sign_param.chain_type,
                network: sign_param.network,
                seg_wit: sign_param.seg_wit,
            }
            .sign_message_async(
                &js_transport(),
                BtcMessageInput {
                    message: input.message,
                    signature_type: parse_btc_signature_type(input.signature_type)?,
                },
            )
            .await
            .map_err(map_err)?;
            serde_json::to_string(&MessageOutputJson {
                signature: output.signature,
            })
            .map_err(|_| js_err("serialize_sign_message_error"))
        }
        _ => Err(js_err("sign_message unsupported_chain")),
    }
}

#[wasm_bindgen]
pub async fn sign_psbt(params_json: &str) -> Result<String, JsValue> {
    let params: SignParamJson =
        serde_json::from_str(params_json).map_err(|_| js_err("imkey_illegal_param"))?;
    if !params.chain_type.eq_ignore_ascii_case("BITCOIN") {
        return Err(js_err("sign_psbt unsupported_chain"));
    }
    let input: PsbtInputJson =
        serde_json::from_value(params.input).map_err(|_| js_err("imkey_illegal_param"))?;
    let output = sign_psbt_async(
        &js_transport(),
        &params.path,
        PsbtInput {
            psbt: input.psbt,
            auto_finalize: input.auto_finalize,
        },
        parse_bitcoin_network(&params.network)?,
    )
    .await
    .map_err(map_err)?;
    serde_json::to_string(&PsbtOutputJson { psbt: output.psbt })
        .map_err(|_| js_err("serialize_sign_psbt_error"))
}

#[wasm_bindgen]
pub async fn device_connect() -> Result<(), JsValue> {
    Err(js_err("imkey_device_connect_not_applicable_in_webusb"))
}

#[wasm_bindgen]
pub async fn cos_update() -> Result<(), JsValue> {
    Err(js_err("imkey_cos_update_not_supported_in_webusb_yet"))
}

#[wasm_bindgen]
pub async fn cos_check_update() -> Result<String, JsValue> {
    Err(js_err("imkey_cos_check_update_not_supported_in_webusb_yet"))
}

#[wasm_bindgen]
pub async fn is_bl_status() -> Result<bool, JsValue> {
    Err(js_err("imkey_bl_status_not_supported_in_webusb_yet"))
}
