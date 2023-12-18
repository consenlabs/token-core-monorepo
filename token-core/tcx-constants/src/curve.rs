use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CurveType {
    SECP256k1,          /* "secp256k1" */
    ED25519,            /* "ed25519" */
    ED25519Blake2bNano, /* "ed25519-blake2b-nano" */
    SubSr25519,
    Curve25519, /* "curve25519" */
    NIST256p1,
    BLS, /* "bls" */
}

impl CurveType {
    pub fn as_str(&self) -> &str {
        match self {
            CurveType::SECP256k1 => "SECP256k1",
            CurveType::ED25519 => "ED25519",
            CurveType::ED25519Blake2bNano => "ED25519Blake2bNano",
            CurveType::SubSr25519 => "SubSr25519",
            CurveType::Curve25519 => "Curve25519",
            CurveType::NIST256p1 => "NIST256p1",
            CurveType::BLS => "BLS",
        }
    }

    pub fn from_str(value: &str) -> CurveType {
        match value {
            "SECP256k1" => CurveType::SECP256k1,
            "ED25519" => CurveType::ED25519,
            "ED25519Blake2bNano" => CurveType::ED25519Blake2bNano,
            "SubSr25519" => CurveType::SubSr25519,
            "Curve25519" => CurveType::Curve25519,
            "NIST256p1" => CurveType::NIST256p1,
            "BLS" => CurveType::BLS,
            _ => panic!("Invalid curve type"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::CurveType;

    #[test]
    fn test_curve_type_as_str() {
        assert_eq!(CurveType::SECP256k1.as_str(), "SECP256k1");
        assert_eq!(CurveType::ED25519.as_str(), "ED25519");
        assert_eq!(CurveType::ED25519Blake2bNano.as_str(), "ED25519Blake2bNano");
        assert_eq!(CurveType::SubSr25519.as_str(), "SubSr25519");
        assert_eq!(CurveType::Curve25519.as_str(), "Curve25519");
        assert_eq!(CurveType::NIST256p1.as_str(), "NIST256p1");
        assert_eq!(CurveType::BLS.as_str(), "BLS");
    }

    #[test]
    fn test_curve_type_from_str() {
        let curve_type = CurveType::from_str("SECP256k1");
        assert_eq!(curve_type, CurveType::SECP256k1);
        let curve_type = CurveType::from_str("ED25519");
        assert_eq!(curve_type, CurveType::ED25519);
        let curve_type = CurveType::from_str("ED25519Blake2bNano");
        assert_eq!(curve_type, CurveType::ED25519Blake2bNano);
        let curve_type = CurveType::from_str("SubSr25519");
        assert_eq!(curve_type, CurveType::SubSr25519);
        let curve_type = CurveType::from_str("Curve25519");
        assert_eq!(curve_type, CurveType::Curve25519);
        let curve_type = CurveType::from_str("NIST256p1");
        assert_eq!(curve_type, CurveType::NIST256p1);
        let curve_type = CurveType::from_str("BLS");
        assert_eq!(curve_type, CurveType::BLS);
    }

    /*    #[test]
       #[should_panic(expected = "Invalid curve type")]
    */
    fn test_curve_type_from_str_invalid_curve_type() {
        let actual = CurveType::from_str("TEST");
    }
}
