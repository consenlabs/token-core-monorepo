use serde::{Deserialize, Serialize};
use tcx_keystore::identity::Identity;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeystoreParam {
    pub prf_key: Option<String>,
    pub password: Option<String>,
    pub user_id: Option<String>,
    pub credential_id: Option<String>,
    pub rp_id: Option<String>,
    pub mnemonic: Option<String>,
    pub entropy: Option<String>,
    pub network: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyKeystore {
    pub user_id: String,
    pub credential_id: String,
    pub rp_id: String,
    pub encrypted_mnemonic: String,
    pub mnemonic_iv: String,
    pub created_at: i64,
    pub identity: Identity,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveAccountsParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub derivations: Vec<DerivationItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivationItem {
    pub chain: Option<String>,
    pub derivation_path: String,
    pub chain_id: Option<String>,
    pub network: Option<String>,
    pub seg_wit: Option<String>,
    #[allow(dead_code)]
    pub curve: Option<String>,
    pub contract_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub address: String,
    pub chain: String,
    pub derivation_path: String,
    pub ext_pub_key: String,
    pub public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
    pub network: Option<String>,
    pub seg_wit: Option<String>,
    pub chain_id: Option<String>,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxsParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub txs: Vec<SignTxItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxItem {
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
    pub network: Option<String>,
    pub seg_wit: Option<String>,
    pub chain_id: Option<String>,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TronTxInputJson {
    pub raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTxInputJson {
    pub nonce: String,
    pub gas_price: Option<String>,
    pub gas_limit: String,
    pub to: String,
    pub value: String,
    pub data: Option<String>,
    pub chain_id: String,
    pub tx_type: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub access_list: Option<Vec<AccessListJson>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListJson {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignMessageParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
    pub network: Option<String>,
    pub seg_wit: Option<String>,
    #[allow(dead_code)]
    pub chain_id: Option<String>,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthSignMessageInputJson {
    pub message: String,
    pub signature_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TronSignMessageInputJson {
    pub value: String,
    pub header: Option<String>,
    pub version: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcUtxoJson {
    pub tx_hash: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub derived_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcTxInputJson {
    pub inputs: Vec<BtcUtxoJson>,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub op_return: Option<String>,
    pub change_address_index: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OmniTxInputJson {
    pub inputs: Vec<BtcUtxoJson>,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub property_id: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtomTxInputJson {
    pub raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EosTxInputJson {
    pub chain_id: String,
    pub tx_hexs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EosSignMessageInputJson {
    pub data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TezosTxInputJson {
    pub raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TonTxInputJson {
    pub hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbOutPointJson {
    pub tx_hash: String,
    pub index: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbScriptJson {
    pub args: String,
    pub code_hash: String,
    pub hash_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbCellInputJson {
    pub previous_output: Option<CkbOutPointJson>,
    pub since: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbWitnessJson {
    pub lock: String,
    pub input_type: String,
    pub output_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbCachedCellJson {
    pub capacity: i64,
    pub lock: Option<CkbScriptJson>,
    pub out_point: Option<CkbOutPointJson>,
    pub derived_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CkbTxInputJson {
    pub inputs: Vec<CkbCellInputJson>,
    pub witnesses: Vec<CkbWitnessJson>,
    pub cached_cells: Vec<CkbCachedCellJson>,
    pub tx_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateTxInputJson {
    pub raw_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcSignMessageInputJson {
    pub message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcPsbtInputJson {
    pub psbt: String,
    pub auto_finalize: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcPsbtsInputJson {
    pub psbts: Vec<String>,
    pub auto_finalize: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPsbtParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub chain: Option<String>,
    pub derivation_path: String,
    pub input: BtcPsbtInputJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPsbtsParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub chain: Option<String>,
    pub derivation_path: String,
    pub input: BtcPsbtsInputJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportMnemonicParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
}

// --- Message types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageGetPubkeyParam {
    pub keystore_json: Option<String>,
    pub key: Option<String>,
    pub prf_key: Option<String>,
    pub derivation_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignEventParam {
    pub event: MessageUnsignedEvent,
    pub recipient_pubkey: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUnsignedEvent {
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignedEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageEncryptParam {
    pub server_pubkey: String,
    pub plaintext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDecryptParam {
    pub server_pubkey: String,
    pub encrypted_content: String,
}
