use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeystoreParam {
    pub password: String,
    pub mnemonic: Option<String>,
    pub name: Option<String>,
    pub password_hint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeystoreResult {
    pub id: String,
    pub name: String,
    pub source: String,
    pub created_at: i64,
    pub keystore_json: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveAccountsParam {
    pub keystore_json: String,
    pub password: String,
    pub derivation_path: Option<String>,
    pub chain_id: Option<String>,
    pub network: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub address: String,
    pub derivation_path: String,
    pub ext_pub_key: String,
    pub public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxParam {
    pub keystore_json: String,
    pub password: String,
    pub derivation_path: Option<String>,
    pub input: EthTxInputJson,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTxResult {
    pub signature: String,
    pub tx_hash: String,
}
