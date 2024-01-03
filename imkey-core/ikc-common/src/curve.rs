use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CurveType {
    #[serde(rename = "secp256k1")]
    SECP256k1,
    #[serde(rename = "ed25519")]
    ED25519,
    #[serde(rename = "ed25519-blake2b-nano")]
    ED25519Blake2bNano,
    #[serde(rename = "sr25519")]
    SR25519,
    #[serde(rename = "curve25519")]
    Curve25519,
    #[serde(rename = "nist256p1")]
    NIST256p1,
    #[serde(rename = "bls12-381")]
    BLS,
}

impl CurveType {
    pub fn as_str(&self) -> &str {
        match self {
            CurveType::SECP256k1 => "secp256k1",
            CurveType::ED25519 => "ed25519",
            CurveType::ED25519Blake2bNano => "ed25519-blake2b-nano",
            CurveType::SR25519 => "sr25519",
            CurveType::Curve25519 => "curve25519",
            CurveType::NIST256p1 => "nist256p1",
            CurveType::BLS => "bls12-381",
        }
    }

    pub fn from_str(value: &str) -> CurveType {
        match value {
            "secp256k1" => CurveType::SECP256k1,
            "ed25519" => CurveType::ED25519,
            "ed25519-blake2b-nano" => CurveType::ED25519Blake2bNano,
            "sr25519" => CurveType::SR25519,
            "curve25519" => CurveType::Curve25519,
            "nist256p1" => CurveType::NIST256p1,
            "bls12-381" => CurveType::BLS,
            _ => panic!("Invalid curve type"),
        }
    }
}
