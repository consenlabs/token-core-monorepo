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

#[cfg(test)]
mod test {
    use crate::CurveType;

    #[test]
    fn test_curve_type_as_str() {
        assert_eq!(CurveType::SECP256k1.as_str(), "secp256k1");
        assert_eq!(CurveType::ED25519.as_str(), "ed25519");
        assert_eq!(
            CurveType::ED25519Blake2bNano.as_str(),
            "ed25519-blake2b-nano"
        );
        assert_eq!(CurveType::SR25519.as_str(), "sr25519");
        assert_eq!(CurveType::Curve25519.as_str(), "curve25519");
        assert_eq!(CurveType::NIST256p1.as_str(), "nist256p1");
        assert_eq!(CurveType::BLS.as_str(), "bls12-381");
    }

    #[test]
    fn test_curve_type_from_str() {
        let curve_type = CurveType::from_str("secp256k1");
        assert_eq!(curve_type, CurveType::SECP256k1);
        let curve_type = CurveType::from_str("ed25519");
        assert_eq!(curve_type, CurveType::ED25519);
        let curve_type = CurveType::from_str("ed25519-blake2b-nano");
        assert_eq!(curve_type, CurveType::ED25519Blake2bNano);
        let curve_type = CurveType::from_str("sr25519");
        assert_eq!(curve_type, CurveType::SR25519);
        let curve_type = CurveType::from_str("curve25519");
        assert_eq!(curve_type, CurveType::Curve25519);
        let curve_type = CurveType::from_str("nist256p1");
        assert_eq!(curve_type, CurveType::NIST256p1);
        let curve_type = CurveType::from_str("bls12-381");
        assert_eq!(curve_type, CurveType::BLS);
    }

    /*    #[test]
       #[should_panic(expected = "Invalid curve type")]
    */
    fn test_curve_type_from_str_invalid_curve_type() {
        let actual = CurveType::from_str("TEST");
    }
}
