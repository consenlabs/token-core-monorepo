use crate::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FROM_MNEMONIC: &str = "MNEMONIC";
pub const FROM_KEYSTORE: &str = "KEYSTORE";
pub const FROM_PRIVATE: &str = "PRIVATE";
pub const FROM_WIF: &str = "WIF";
pub const FROM_NEW_IDENTITY: &str = "NEW_IDENTITY";
pub const FROM_RECOVERED_IDENTITY: &str = "RECOVERED_IDENTITY";
pub const P2WPKH: &str = "P2WPKH";
pub const NONE: &str = "NONE";
pub const NORMAL: &str = "NORMAL";
pub const HD: &str = "HD";
pub const RANDOM: &str = "RANDOM";
pub const HD_SHA256: &str = "HD_SHA256";
pub const V3: &str = "V3";

pub const NETWORK_MAINNET: &str = "MAINNET";
pub const NETWORK_TESTNET: &str = "TESTNET";

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    pub password_hint: Option<String>,
    pub chain_type: String,
    pub timestamp: u128,
    pub network: String,
    pub backup: Option<Vec<String>>,
    pub source: String,
    pub mode: Option<String>,
    pub wallet_type: Option<String>,
    pub seg_wit: Option<String>,
}

impl Metadata {
    pub fn new(
        name: &str,
        password_hint: Option<String>,
        source: &str,
        network: &str,
        seg_wit: Option<&str>,
    ) -> Result<Self> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let temp_seg_wit = if let Some(a) = seg_wit {
            Some(a.to_string())
        } else {
            None
        };
        Ok(Metadata {
            name: name.to_string(),
            password_hint,
            chain_type: "".to_string(),
            timestamp,
            network: network.to_string(),
            backup: None,
            source: source.to_string(),
            mode: None,
            wallet_type: None,
            seg_wit: temp_seg_wit,
        })
    }

    pub fn is_main_net(&self) -> bool {
        self.network.eq_ignore_ascii_case(NETWORK_MAINNET)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }
}

#[cfg(test)]
mod test {
    use crate::model::Metadata;
    use crate::model::FROM_NEW_IDENTITY;

    #[test]
    fn test_metadata_new() {
        let mut metadata = Metadata::new(
            "name",
            Some("password_hint".to_string()),
            FROM_NEW_IDENTITY,
            "MAINNET",
            None,
        )
        .unwrap();
        metadata.timestamp = 1686105373257408;
        let metadata_json = metadata.to_json().unwrap();
        let expected_json = "{\"name\":\"name\",\"passwordHint\":\"password_hint\",\"chainType\":\"\",\"timestamp\":1686105373257408,\"network\":\"MAINNET\",\"backup\":null,\"source\":\"NEW_IDENTITY\",\"mode\":null,\"walletType\":null,\"segWit\":null}";
        assert_eq!(metadata_json, expected_json);
        metadata.chain_type = "ETHEREUM".to_string();
        let metadata_json = metadata.to_json().unwrap();
        let expected_json = "{\"name\":\"name\",\"passwordHint\":\"password_hint\",\"chainType\":\"ETHEREUM\",\"timestamp\":1686105373257408,\"network\":\"MAINNET\",\"backup\":null,\"source\":\"NEW_IDENTITY\",\"mode\":null,\"walletType\":null,\"segWit\":null}";
        assert_eq!(metadata_json, expected_json);
    }

    #[test]
    fn test_is_main_net() {
        let mut metadata = Metadata::new(
            "name",
            Some("password_hint".to_string()),
            FROM_NEW_IDENTITY,
            "MAINNET",
            None,
        )
        .unwrap();
        assert_eq!(metadata.is_main_net(), true);
        metadata.network = "TESTNET".to_string();
        assert_eq!(metadata.is_main_net(), false);
        metadata.network = "WRONG_NET".to_string();
        assert_eq!(metadata.is_main_net(), false);
        metadata.network = "".to_string();
        assert_eq!(metadata.is_main_net(), false);
    }
}
