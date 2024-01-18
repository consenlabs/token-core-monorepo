use serde::Serialize;
use tcx_common::{FromHex, ToHex};

use super::{Result, Ss58Codec};
use crate::{
    Bip32DeterministicPrivateKey, Bip32DeterministicPublicKey, Derive, Secp256k1PrivateKey,
    Secp256k1PublicKey,
};

use crate::bls::{BLSPrivateKey, BLSPublicKey};
use crate::bls_derive::BLSDeterministicPrivateKey;
use crate::ecc::TypedDeterministicPrivateKey::{Bip32Ed25519, SR25519};
use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::ed25519_bip32::{Ed25519DeterministicPrivateKey, Ed25519DeterministicPublicKey};
use crate::sr25519::{Sr25519PrivateKey, Sr25519PublicKey};
use sp_core::Pair;
use tcx_constants::CurveType;

#[derive(Fail, Debug, PartialEq)]
pub enum KeyError {
    #[fail(display = "invalid_child_number_format")]
    InvalidChildNumberFormat,
    #[fail(display = "invalid_derivation_path_format")]
    InvalidDerivationPathFormat,
    #[fail(display = "invalid_signature")]
    InvalidSignature,
    #[fail(display = "invalid_child_number")]
    InvalidChildNumber,
    #[fail(display = "cannot_derive_from_hardened_key")]
    CannotDeriveFromHardenedKey,
    // todo: why use this key?
    #[fail(display = "cannot_derive_key")]
    InvalidBase58,
    #[fail(display = "invalid_private_key")]
    InvalidPrivateKey,
    #[fail(display = "invalid_public_key")]
    InvalidPublicKey,
    #[fail(display = "invalid_message")]
    InvalidMessage,
    #[fail(display = "invalid_recovery_id")]
    InvalidRecoveryId,
    #[fail(display = "invalid_tweak")]
    InvalidTweak,
    #[fail(display = "not_enough_memory")]
    NotEnoughMemory,
    #[fail(display = "invalid_curve_type")]
    InvalidCurveType,
    #[fail(display = "invalid_sr25519_key")]
    InvalidSR25519Key,
    #[fail(display = "invalid_ed25519_key")]
    InvalidEd25519Key,
    #[fail(display = "unsupport_ed25519_pubkey_derivation")]
    UnsupportEd25519PubkeyDerivation,
    #[fail(display = "unsupport_normal_derivation")]
    UnsupportNormalDerivation,
    #[fail(display = "not_implement")]
    NotImplement,
    #[fail(display = "secp256k1_error")]
    Secp256k1,
    #[fail(display = "unknown_version")]
    UnknownVersion,
    #[fail(display = "wrong_extended_key_length")]
    WrongExtendedKeyLength,
    #[fail(display = "base58_encoding_error")]
    Base58,
    #[fail(display = "hexadecimal_decoding_error")]
    Hex,
    #[fail(display = "invalid_bls_key")]
    InvalidBlsKey,
}

pub trait PublicKey: Sized {
    fn from_slice(data: &[u8]) -> Result<Self>;

    fn to_bytes(&self) -> Vec<u8>;
}

pub trait PrivateKey: Sized {
    type PublicKey: PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self>;

    fn public_key(&self) -> Self::PublicKey;

    fn sign(&self, _: &[u8]) -> Result<Vec<u8>>;

    fn sign_specified_hash(&self, _: &[u8], dst: &str) -> Result<Vec<u8>>;

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>>;

    fn to_bytes(&self) -> Vec<u8>;
}

pub trait DeterministicPublicKey: Derive + ToHex + FromHex {
    type PublicKey: PublicKey;

    fn public_key(&self) -> Self::PublicKey;
}

pub trait DeterministicPrivateKey: Derive {
    type DeterministicPublicKey: DeterministicPublicKey;
    type PrivateKey: PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self>;

    fn from_mnemonic(mnemonic: &str) -> Result<Self>;

    fn private_key(&self) -> Self::PrivateKey;

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey;
}

pub trait TypedPrivateKeyDisplay {
    fn fmt(data: &[u8], network: &str) -> Result<String>;
}

pub enum TypedPrivateKey {
    Secp256k1(Secp256k1PrivateKey),
    SR25519(Sr25519PrivateKey),
    Ed25519(Ed25519PrivateKey),
    BLS(BLSPrivateKey),
}

impl TypedPrivateKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedPrivateKey::Secp256k1(_) => CurveType::SECP256k1,
            TypedPrivateKey::SR25519(_) => CurveType::SR25519,
            TypedPrivateKey::Ed25519(_) => CurveType::ED25519,
            TypedPrivateKey::BLS(_) => CurveType::BLS,
        }
    }

    pub fn from_slice(curve_type: CurveType, data: &[u8]) -> Result<TypedPrivateKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedPrivateKey::Secp256k1(
                Secp256k1PrivateKey::from_slice(data)?,
            )),
            CurveType::SR25519 => Ok(TypedPrivateKey::SR25519(Sr25519PrivateKey::from_slice(
                data,
            )?)),
            CurveType::ED25519 => Ok(TypedPrivateKey::Ed25519(Ed25519PrivateKey::from_slice(
                data,
            )?)),
            CurveType::BLS => Ok(TypedPrivateKey::BLS(BLSPrivateKey::from_slice(data)?)),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn as_secp256k1(&self) -> Result<&Secp256k1PrivateKey> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => Ok(sk),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.to_bytes(),
            TypedPrivateKey::SR25519(sk) => sk.to_bytes(),
            TypedPrivateKey::Ed25519(sk) => sk.to_bytes(),
            TypedPrivateKey::BLS(sk) => sk.to_bytes(),
        }
    }

    pub fn public_key(&self) -> TypedPublicKey {
        match self {
            TypedPrivateKey::Secp256k1(sk) => TypedPublicKey::Secp256k1(sk.public_key()),
            TypedPrivateKey::SR25519(sk) => TypedPublicKey::SR25519(sk.public_key()),
            TypedPrivateKey::Ed25519(sk) => TypedPublicKey::Ed25519(sk.public_key()),
            TypedPrivateKey::BLS(sk) => TypedPublicKey::BLS(sk.public_key()),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.sign(data),
            TypedPrivateKey::SR25519(sk) => sk.sign(data),
            TypedPrivateKey::Ed25519(sk) => sk.sign(data),
            TypedPrivateKey::BLS(sk) => sk.sign(data),
        }
    }

    pub fn sign_specified_hash(&self, data: &[u8], dst: &str) -> Result<Vec<u8>> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.sign_specified_hash(data, dst),
            TypedPrivateKey::SR25519(sk) => sk.sign_specified_hash(data, dst),
            TypedPrivateKey::Ed25519(sk) => sk.sign_specified_hash(data, dst),
            TypedPrivateKey::BLS(sk) => sk.sign_specified_hash(data, dst),
        }
    }

    pub fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TypedPrivateKey::Secp256k1(sk) => sk.sign_recoverable(data),
            TypedPrivateKey::SR25519(sk) => sk.sign_recoverable(data),
            TypedPrivateKey::Ed25519(sk) => sk.sign_recoverable(data),
            TypedPrivateKey::BLS(sk) => sk.sign_recoverable(data),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypedPublicKey {
    Secp256k1(Secp256k1PublicKey),
    SR25519(Sr25519PublicKey),
    Ed25519(Ed25519PublicKey),
    BLS(BLSPublicKey),
}

impl TypedPublicKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedPublicKey::Secp256k1(_) => CurveType::SECP256k1,
            TypedPublicKey::SR25519(_) => CurveType::SR25519,
            TypedPublicKey::Ed25519(_) => CurveType::ED25519,
            TypedPublicKey::BLS(_) => CurveType::BLS,
        }
    }

    pub fn from_slice(curve_type: CurveType, data: &[u8]) -> Result<TypedPublicKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedPublicKey::Secp256k1(Secp256k1PublicKey::from_slice(
                data,
            )?)),
            CurveType::SR25519 => Ok(TypedPublicKey::SR25519(Sr25519PublicKey::from_slice(data)?)),
            CurveType::ED25519 => Ok(TypedPublicKey::Ed25519(Ed25519PublicKey::from_slice(data)?)),
            CurveType::BLS => Ok(TypedPublicKey::BLS(BLSPublicKey::from_slice(data)?)),

            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TypedPublicKey::Secp256k1(pk) => pk.to_bytes(),
            TypedPublicKey::SR25519(pk) => pk.to_bytes(),
            TypedPublicKey::Ed25519(pk) => pk.to_bytes(),
            TypedPublicKey::BLS(pk) => pk.to_bytes(),
        }
    }

    pub fn as_secp256k1(&self) -> Result<&Secp256k1PublicKey> {
        match self {
            TypedPublicKey::Secp256k1(pk) => Ok(pk),
            _ => Err(format_err!("not support")),
        }
    }
}

pub enum TypedDeterministicPublicKey {
    Bip32Sepc256k1(Bip32DeterministicPublicKey),
    SR25519(Sr25519PublicKey),
    Bip32Ed25519(Ed25519DeterministicPublicKey),
}

impl TypedDeterministicPublicKey {
    pub fn from_ss58check(curve: CurveType, ss58check: &str) -> Result<Self> {
        match curve {
            CurveType::SECP256k1 => {
                let (bip32, _) =
                    Bip32DeterministicPublicKey::from_ss58check_with_version(ss58check)?;
                Ok(TypedDeterministicPublicKey::Bip32Sepc256k1(bip32))
            }
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => {
                epk.to_ss58check_with_version(version)
            }
            _ => "".to_owned(),
        }
    }
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(_) => CurveType::SECP256k1,
            TypedDeterministicPublicKey::SR25519(_) => CurveType::SR25519,
            TypedDeterministicPublicKey::Bip32Ed25519(_) => CurveType::ED25519,
        }
    }

    pub fn fingerprint(&self) -> Result<Vec<u8>> {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => Ok(epk.fingerprint()),
            _ => Err(format_err!("bls or ed25519 not support fingerprint")),
        }
    }

    pub fn public_key(&self) -> TypedPublicKey {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => {
                TypedPublicKey::Secp256k1(epk.public_key())
            }
            TypedDeterministicPublicKey::SR25519(epk) => TypedPublicKey::SR25519(epk.public_key()),
            TypedDeterministicPublicKey::Bip32Ed25519(epk) => {
                TypedPublicKey::Ed25519(epk.public_key())
            }
        }
    }
}

impl ToString for TypedDeterministicPublicKey {
    fn to_string(&self) -> String {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => epk.to_string(),
            TypedDeterministicPublicKey::SR25519(epk) => epk.to_string(),
            TypedDeterministicPublicKey::Bip32Ed25519(epk) => epk.to_string(),
        }
    }
}

impl Derive for TypedDeterministicPublicKey {
    fn derive(&self, path: &str) -> Result<Self> {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => Ok(
                TypedDeterministicPublicKey::Bip32Sepc256k1(epk.derive(path)?),
            ),
            TypedDeterministicPublicKey::SR25519(epk) => {
                Ok(TypedDeterministicPublicKey::SR25519(epk.derive(path)?))
            }
            TypedDeterministicPublicKey::Bip32Ed25519(epk) => {
                Ok(TypedDeterministicPublicKey::Bip32Ed25519(epk.derive(path)?))
            }
        }
    }
}

#[derive(Clone)]
pub enum TypedDeterministicPrivateKey {
    Bip32Sepc256k1(Bip32DeterministicPrivateKey),
    SR25519(Sr25519PrivateKey),
    Bip32Ed25519(Ed25519DeterministicPrivateKey),
    BLS(BLSDeterministicPrivateKey),
}

impl TypedDeterministicPrivateKey {
    pub fn curve_type(&self) -> CurveType {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(_) => CurveType::SECP256k1,
            TypedDeterministicPrivateKey::SR25519(_) => CurveType::SR25519,
            TypedDeterministicPrivateKey::Bip32Ed25519(_) => CurveType::ED25519,
            TypedDeterministicPrivateKey::BLS(_) => CurveType::BLS,
        }
    }

    pub fn from_mnemonic(
        curve_type: CurveType,
        mnemonic: &str,
    ) -> Result<TypedDeterministicPrivateKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedDeterministicPrivateKey::Bip32Sepc256k1(
                Bip32DeterministicPrivateKey::from_mnemonic(mnemonic)?,
            )),
            CurveType::SR25519 => Ok(SR25519(Sr25519PrivateKey::from_mnemonic(mnemonic)?)),
            CurveType::ED25519 => Ok(Bip32Ed25519(Ed25519DeterministicPrivateKey::from_mnemonic(
                mnemonic,
            )?)),
            CurveType::BLS => Ok(TypedDeterministicPrivateKey::BLS(
                BLSDeterministicPrivateKey::from_mnemonic(mnemonic)?,
            )),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }

    pub fn private_key(&self) -> TypedPrivateKey {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(dsk) => {
                TypedPrivateKey::Secp256k1(dsk.private_key())
            }
            TypedDeterministicPrivateKey::SR25519(dsk) => {
                TypedPrivateKey::SR25519(dsk.private_key())
            }
            TypedDeterministicPrivateKey::Bip32Ed25519(dsk) => {
                TypedPrivateKey::Ed25519(dsk.private_key())
            }
            TypedDeterministicPrivateKey::BLS(dsk) => TypedPrivateKey::BLS(dsk.private_key()),
        }
    }

    pub fn deterministic_public_key(&self) -> TypedDeterministicPublicKey {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(sk) => {
                TypedDeterministicPublicKey::Bip32Sepc256k1(sk.deterministic_public_key())
            }
            TypedDeterministicPrivateKey::SR25519(sk) => {
                TypedDeterministicPublicKey::SR25519(sk.deterministic_public_key())
            }
            TypedDeterministicPrivateKey::Bip32Ed25519(sk) => {
                TypedDeterministicPublicKey::Bip32Ed25519(sk.deterministic_public_key())
            }
            TypedDeterministicPrivateKey::BLS(_) => panic!("not support"),
        }
    }
}

impl ToString for TypedDeterministicPrivateKey {
    fn to_string(&self) -> String {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(sk) => sk.to_string(),
            TypedDeterministicPrivateKey::SR25519(sk) => sk.0.to_raw_vec().to_hex(),
            TypedDeterministicPrivateKey::Bip32Ed25519(sk) => sk.to_string(),
            TypedDeterministicPrivateKey::BLS(sk) => sk.0.to_string(),
        }
    }
}

impl TypedDeterministicPublicKey {
    pub fn from_hex(curve_type: CurveType, hex: &str) -> Result<TypedDeterministicPublicKey> {
        match curve_type {
            CurveType::SECP256k1 => Ok(TypedDeterministicPublicKey::Bip32Sepc256k1(
                Bip32DeterministicPublicKey::from_hex(hex)?,
            )),
            CurveType::SR25519 => Ok(TypedDeterministicPublicKey::SR25519(
                Sr25519PublicKey::from_hex(hex)?,
            )),
            CurveType::ED25519 => Ok(TypedDeterministicPublicKey::Bip32Ed25519(
                Ed25519DeterministicPublicKey::from_hex(hex)?,
            )),
            _ => Err(KeyError::InvalidCurveType.into()),
        }
    }
}

impl ToHex for TypedDeterministicPublicKey {
    fn to_hex(&self) -> String {
        match self {
            TypedDeterministicPublicKey::Bip32Sepc256k1(epk) => epk.to_hex(),
            TypedDeterministicPublicKey::SR25519(epk) => epk.to_hex(),
            TypedDeterministicPublicKey::Bip32Ed25519(epk) => epk.to_hex(),
        }
    }
}

impl Derive for TypedDeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        match self {
            TypedDeterministicPrivateKey::Bip32Sepc256k1(dsk) => Ok(
                TypedDeterministicPrivateKey::Bip32Sepc256k1(dsk.derive(path)?),
            ),
            TypedDeterministicPrivateKey::SR25519(dsk) => {
                Ok(TypedDeterministicPrivateKey::SR25519(dsk.derive(path)?))
            }
            TypedDeterministicPrivateKey::Bip32Ed25519(dsk) => Ok(
                TypedDeterministicPrivateKey::Bip32Ed25519(dsk.derive(path)?),
            ),
            TypedDeterministicPrivateKey::BLS(dsk) => {
                Ok(TypedDeterministicPrivateKey::BLS(dsk.derive(path)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PrivateKey, PublicKey, TypedDeterministicPrivateKey, TypedPrivateKey};
    use crate::{bls::BLSPrivateKey, Derive, Sr25519PrivateKey, TypedPublicKey};
    use bip39::{Language, Mnemonic, Seed};
    use tcx_common::{FromHex, ToHex};

    use tcx_constants::{CurveType, TEST_MNEMONIC};

    #[allow(dead_code)]
    fn default_seed() -> Seed {
        let mn = Mnemonic::from_phrase(
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            Language::English,
        )
        .unwrap();
        Seed::new(&mn, "")
    }

    fn default_private_key() -> Vec<u8> {
        Vec::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap()
    }

    const PUB_KEY_HEX: &'static str =
        "02b95c249d84f417e3e395a127425428b540671cc15881eb828c17b722a53fc599";

    const SR25519_PRI_KEY_HEX: &str =
        "00ea01b0116da6ca425c477521fd49cc763988ac403ab560f4022936a18a4341016e7df1f5020068c9b150e0722fea65a264d5fbb342d4af4ddf2f1cdbddf1fd";

    const SR25519_PUB_KEY_HEX: &str =
        "fc581c897af481b10cf846d88754f1d115e486e5b7bcc39c0588c01b0a9b7a11";

    #[test]
    fn typed_private_key() {
        let ret = TypedPrivateKey::from_slice(CurveType::ED25519, &default_private_key());
        assert!(ret.is_ok());

        let sk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &default_private_key()).unwrap();

        assert_eq!(sk.to_bytes(), default_private_key());
        assert_eq!(sk.as_secp256k1().unwrap().to_bytes(), default_private_key());
        assert_eq!(sk.curve_type(), CurveType::SECP256k1);
        assert_eq!(sk.public_key().to_bytes().to_hex(), PUB_KEY_HEX);

        let sign_ret = sk.sign(&default_private_key()).unwrap();
        assert_eq!(sign_ret.to_hex(), "304402206614e4bfa3ba1f6c975286a0a683871d6f0525a0860631afa5bea4da78ca012a02207a663d4980abed218683f66a63bbb766975fd525b8442a0424f6347c3d4f9261");
    }

    #[test]
    fn typed_deterministic_private_key() {
        let root =
            TypedDeterministicPrivateKey::from_mnemonic(CurveType::SECP256k1, &TEST_MNEMONIC)
                .unwrap();

        let dpk = root
            .derive("m/44'/0'/0'")
            .unwrap()
            .deterministic_public_key();

        assert_eq!(dpk.to_string(), "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");
        assert_eq!(
            dpk.fingerprint().unwrap().to_hex(),
            "a6381e76634d662f9f66a1d0f43cc058102e98c5"
        );
        assert_eq!(dpk.curve_type(), CurveType::SECP256k1);
        assert_eq!(
            dpk.public_key().to_bytes().to_hex(),
            "029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77"
        );
        let child_dpk = dpk.derive("0/0").unwrap();
        assert_eq!(child_dpk.to_string(), "xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX");

        let child_dpk = dpk.derive("m/0/0").unwrap();
        assert_eq!(child_dpk.to_string(), "xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX");

        let dsk = root.derive("m/44'/0'/0'").unwrap();

        assert_eq!(dsk.to_string(), "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ");
    }

    #[test]
    fn typed_deterministic_private_key_sr25519() {
        let root = TypedDeterministicPrivateKey::from_mnemonic(CurveType::SR25519, &TEST_MNEMONIC)
            .unwrap();

        let dpk = root
            .derive("m/44'/0'/0'")
            .unwrap()
            .deterministic_public_key();

        assert_eq!(
            dpk.to_string(),
            "5Cntm6VLcdbFTSKUqyjuTjEfYrJgQparwoio6Coutb18Jbjv"
        );
        assert_eq!(dpk.curve_type(), CurveType::SR25519);
        assert_eq!(
            dpk.public_key().to_bytes().to_hex(),
            "202d03479aee4051f74ec9edf422b1a5272eee3720d29b3b2b9587a32faf450f"
        );
        let child_dpk = dpk.derive("0/0").unwrap();
        assert_eq!(
            child_dpk.to_string(),
            "5FCuuGpkXAqc4WG5JgV6yFmAt1tykiuXCEb5yRGacGcoxkSh"
        );

        let child_dpk = dpk.derive("m/0/0").unwrap();
        assert_eq!(
            child_dpk.to_string(),
            "5Dt1Pst8UQBuYv83dcNi1BDpCQPsXHLMwNDPr4efev1psrEB"
        );
    }

    #[test]
    fn typed_deterministic_private_key_ed25519() {
        let root = TypedDeterministicPrivateKey::from_mnemonic(CurveType::ED25519, &TEST_MNEMONIC)
            .unwrap();

        let dpk = root
            .derive("m/44'/0'/0'")
            .unwrap()
            .deterministic_public_key();

        assert_eq!(
            dpk.to_string(),
            "636fe2cbc0741584e6b71dc00a3fc85e1f616f98a2b21eb8e1fd86bc1e4e3bf3"
        );
        assert_eq!(dpk.curve_type(), CurveType::ED25519);
        assert_eq!(
            dpk.public_key().to_bytes().to_hex(),
            "636fe2cbc0741584e6b71dc00a3fc85e1f616f98a2b21eb8e1fd86bc1e4e3bf3"
        );
    }

    #[test]
    fn test_typed_public_key() {
        let pub_key = Vec::from_hex(PUB_KEY_HEX).unwrap();

        let pk = TypedPublicKey::from_slice(CurveType::SECP256k1, &pub_key).unwrap();

        assert_eq!(pk.curve_type(), CurveType::SECP256k1);

        assert_eq!(pk.to_bytes().to_hex(), PUB_KEY_HEX);
        assert_eq!(pk.as_secp256k1().unwrap().to_bytes().to_hex(), PUB_KEY_HEX);
        assert_eq!(pk.curve_type(), CurveType::SECP256k1);

        let pk = TypedPublicKey::from_slice(
            CurveType::SR25519,
            Vec::from_hex(SR25519_PUB_KEY_HEX).unwrap().as_slice(),
        )
        .unwrap();
        assert_eq!(pk.curve_type(), CurveType::SR25519);
        assert_eq!(pk.to_bytes().to_hex(), SR25519_PUB_KEY_HEX);
    }

    #[test]
    fn test_sign_specified_hash() {
        let message = "0000000000000000000000000000000000000000000000000000000000000000".as_bytes();
        let sk = TypedPrivateKey::from_slice(CurveType::SECP256k1, &default_private_key()).unwrap();
        let sign_ret = sk.sign_specified_hash(message, "blake2b");
        assert_eq!(sign_ret.err().unwrap().to_string(), "not_implement");

        let sk = TypedPrivateKey::from_slice(CurveType::ED25519, &default_private_key()).unwrap();
        let sign_ret = sk.sign_specified_hash(message, "blake2b");
        assert_eq!(sign_ret.err().unwrap().to_string(), "not_implement");

        let sk = TypedPrivateKey::from_slice(CurveType::SR25519, message).unwrap();
        let sign_ret = sk.sign_specified_hash(message, "blake2b");
        assert_eq!(sign_ret.err().unwrap().to_string(), "not_implement");
    }

    #[test]
    fn test_sign_recoverable() {
        let message = "0000000000000000000000000000000000000000000000000000000000000000".as_bytes();
        let sk = TypedPrivateKey::from_slice(CurveType::ED25519, &default_private_key()).unwrap();
        let sign_ret = sk.sign_recoverable(message).unwrap();
        assert_eq!(sign_ret.to_hex(), "65879392febf60e1fe01dfc301832c45b978f154639b2b0a3137264acc56bf41c380a81d73fa621753236dcab456afff2a4228f16fb80cce249dff3a8d7bf90b");

        let sk = TypedPrivateKey::from_slice(CurveType::SR25519, message).unwrap();
        let sign_ret = sk.sign_recoverable(message);
        assert!(sign_ret.is_ok());
    }

    #[test]
    fn cross_test_tw() {
        let root =
            TypedDeterministicPrivateKey::from_mnemonic(CurveType::SECP256k1, "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal")
                .unwrap();

        let dpk = root
            .derive("m/84'/0'/0'/0/0")
            .unwrap()
            .deterministic_public_key();
        assert_eq!(
            dpk.public_key().to_bytes().to_hex(),
            "02df9ef2a7a5552765178b181e1e1afdefc7849985c7dfe9647706dd4fa40df6ac"
        );

        let dpk = root
            .derive("m/84'/0'/0'/0/2")
            .unwrap()
            .deterministic_public_key();
        assert_eq!(
            dpk.public_key().to_bytes().to_hex(),
            "031e1f64d2f6768dccb6814545b2e2d58e26ad5f91b7cbaffe881ed572c65060db"
        );

        let dsk = root.derive("m/44'/539'/0'/0/0").unwrap();
        assert_eq!(
            dsk.private_key().to_bytes().to_hex(),
            "4fb8657d6464adcaa086d6758d7f0b6b6fc026c98dc1671fcc6460b5a74abc62"
        );
    }

    #[test]
    fn test_bip49_spec_vertors() {
        let root =
            TypedDeterministicPrivateKey::from_mnemonic(CurveType::SECP256k1, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .unwrap();
        let pri_key = root.derive("m/49'/1'/0'").unwrap();
        assert_eq!(
            pri_key.to_string(),
            "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n"
        );
        assert_eq!(
            pri_key.deterministic_public_key().to_string(),
            "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"
        );
    }
}
