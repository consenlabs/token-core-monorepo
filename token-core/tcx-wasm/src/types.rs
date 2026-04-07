use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeystoreParam {
    pub prf_key: String,
    pub user_id: String,
    pub credential_id: String,
    pub rp_id: String,
    pub mnemonic: Option<String>,
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveAccountsParam {
    pub keystore_json: String,
    pub prf_key: String,
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
    pub prf_key: String,
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
