use std::{fmt, str::FromStr};

use failure::format_err;
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

impl FromStr for CurveType {
    type Err = failure::Error;

    fn from_str(input: &str) -> std::result::Result<CurveType, Self::Err> {
        match input {
            "SECP256k1" => Ok(CurveType::SECP256k1),
            "ED25519" => Ok(CurveType::ED25519),
            "ED25519Blake2bNano" => Ok(CurveType::ED25519Blake2bNano),
            "SubSr25519" => Ok(CurveType::SubSr25519),
            "Curve25519" => Ok(CurveType::Curve25519),
            "NIST256p1" => Ok(CurveType::NIST256p1),
            "BLS" => Ok(CurveType::BLS),
            _ => Err(format_err!("Invalid curve type")),
        }
    }
}

impl fmt::Display for CurveType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let curve_str = match self {
            CurveType::SECP256k1 => "SECP256k1",
            CurveType::ED25519 => "ED25519",
            CurveType::ED25519Blake2bNano => "ED25519Blake2bNano",
            CurveType::SubSr25519 => "SubSr25519",
            CurveType::Curve25519 => "Curve25519",
            CurveType::NIST256p1 => "NIST256p1",
            CurveType::BLS => "BLS",
        };

        write!(f, "{}", curve_str)
    }
}

// impl CurveType {
//     pub fn as_str(&self) -> &str {
//         match self {
//             CurveType::SECP256k1 => "SECP256k1",
//             CurveType::ED25519 => "ED25519",
//             CurveType::ED25519Blake2bNano => "ED25519Blake2bNano",
//             CurveType::SubSr25519 => "SubSr25519",
//             CurveType::Curve25519 => "Curve25519",
//             CurveType::NIST256p1 => "NIST256p1",
//             CurveType::BLS => "BLS",
//         }
//     }

//     pub fn from_str(value: &str) -> CurveType {
//         match value {
//             "SECP256k1" => CurveType::SECP256k1,
//             "ED25519" => CurveType::ED25519,
//             "ED25519Blake2bNano" => CurveType::ED25519Blake2bNano,
//             "SubSr25519" => CurveType::SubSr25519,
//             "Curve25519" => CurveType::Curve25519,
//             "NIST256p1" => CurveType::NIST256p1,
//             "BLS" => CurveType::BLS,
//             _ => panic!("Invalid curve type"),
//         }
//     }
// }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SigAlg {
    ECDSA,
    Schnorr,
    EdDSA,
    BlsSigBls12381g2Xmd,
    Other(String),
}

impl SigAlg {
    pub fn as_str(&self) -> &str {
        match self {
            SigAlg::ECDSA => "ECDSA",
            SigAlg::Schnorr => "Schnorr",
            SigAlg::EdDSA => "EdDSA",
            SigAlg::BlsSigBls12381g2Xmd => "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            SigAlg::Other(alg) => alg.as_str(),
        }
    }

    pub fn from_str(value: &str) -> SigAlg {
        match value {
            "ECDSA" => SigAlg::ECDSA,
            "Schnorr" => SigAlg::Schnorr,
            "EdDSA" => SigAlg::EdDSA,
            "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" => SigAlg::BlsSigBls12381g2Xmd,
            other => SigAlg::Other(other.to_string()),
        }
    }
}
