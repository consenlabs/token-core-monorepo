use serde::{Deserialize, Serialize};
use tcx_keystore::identity::Identity;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeystoreParam {
    pub prf_key: String,
    pub user_id: String,
    pub credential_id: String,
    pub rp_id: String,
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
    pub prf_key: String,
    pub derivations: Vec<DerivationItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivationItem {
    pub chain: Option<String>,
    pub derivation_path: String,
    pub chain_id: Option<String>,
    pub network: Option<String>,
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
    pub prf_key: String,
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
    pub input: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxsParam {
    pub keystore_json: Option<String>,
    pub prf_key: String,
    pub txs: Vec<SignTxItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxItem {
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
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
    pub prf_key: String,
    pub chain: Option<String>,
    pub derivation_path: Option<String>,
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

// --- Message types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageGetPubkeyParam {
    pub keystore_json: Option<String>,
    pub prf_key: String,
    pub derivation_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignEventParam {
    pub keystore_json: Option<String>,
    pub prf_key: String,
    pub derivation_path: Option<String>,
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
