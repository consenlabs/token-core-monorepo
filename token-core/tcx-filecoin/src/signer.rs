use crate::transaction::{Signature, SignedMessage, UnsignedMessage};
use crate::utils::{digest, HashSize};
use crate::Error;
use anyhow::anyhow;
use fvm_shared::address::Address;
use std::borrow::Cow;

// use forest_cid::Cid;
// use forest_encoding::Cbor;
// use forest_message::UnsignedMessage as ForestUnsignedMessage;
use fvm_shared::message::Message as ForestUnsignedMessage;
// use forest_vm::{Serialized, TokenAmount};
use cid::{Cid, CidGeneric};
use std::convert::TryFrom;
use std::str::FromStr;
// use forest_encoding::Cbor;
use fvm_ipld_encoding::RawBytes;
// use forest_vm::Serialized;
use crate::utils::CidCborExt;
use fvm_ipld_encoding::{
    de,
    repr::{Deserialize_repr, Serialize_repr},
    ser, strict_bytes,
};
use fvm_shared::bigint::BigInt;
use fvm_shared::econ::TokenAmount;
use serde_tuple::{self, Deserialize_tuple, Serialize_tuple};
use tcx_constants::CurveType;
use tcx_keystore::{tcx_ensure, Keystore, Result, SignatureParameters, Signer, TransactionSigner};

use num::FromPrimitive;
use num_derive::FromPrimitive;
use strum::*;

#[derive(
    Clone,
    Debug,
    PartialEq,
    FromPrimitive,
    Copy,
    Eq,
    Serialize_repr,
    Deserialize_repr,
    Hash,
    strum::Display,
    strum::EnumString,
)]
#[repr(u8)]
#[strum(serialize_all = "lowercase")]
pub enum SignatureType {
    Secp256k1 = 1,
    Bls = 2,
    Delegated = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ForestSignature {
    pub sig_type: SignatureType,
    pub bytes: Vec<u8>,
}

impl ser::Serialize for ForestSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut bytes = Vec::with_capacity(self.bytes.len() + 1);
        // Insert signature type byte
        bytes.push(self.sig_type as u8);
        bytes.extend_from_slice(&self.bytes);

        strict_bytes::Serialize::serialize(&bytes, serializer)
    }
}

impl<'de> de::Deserialize<'de> for ForestSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: Cow<'de, [u8]> = strict_bytes::Deserialize::deserialize(deserializer)?;
        match bytes.split_first() {
            None => Err(de::Error::custom("Cannot deserialize empty bytes")),
            Some((&sig_byte, rest)) => {
                // Remove signature type byte
                let sig_type = SignatureType::from_u8(sig_byte).ok_or_else(|| {
                    de::Error::custom(format!(
                        "Invalid signature type byte (must be 1, 2 or 3), was {}",
                        sig_byte
                    ))
                })?;

                Ok(ForestSignature {
                    bytes: rest.to_vec(),
                    sig_type,
                })
            }
        }
    }
}

#[derive(PartialEq, Clone, Debug, Serialize_tuple, Deserialize_tuple, Hash, Eq)]
pub struct ForestSignedMessage {
    pub message: ForestUnsignedMessage,
    pub signature: ForestSignature,
}

fn str_to_token_amount(str: &str) -> TokenAmount {
    TokenAmount::from_atto(u64::from_str(str).unwrap())
}

impl TryFrom<&UnsignedMessage> for ForestUnsignedMessage {
    type Error = crate::Error;

    fn try_from(
        message: &UnsignedMessage,
    ) -> core::result::Result<ForestUnsignedMessage, Self::Error> {
        let to = Address::from_str(&message.to).map_err(|_| Error::InvalidAddress)?;
        let from = Address::from_str(&message.from).map_err(|_| Error::InvalidAddress)?;
        let value = str_to_token_amount(&message.value);
        let gas_limit = message.gas_limit;
        let gas_fee_cap = str_to_token_amount(&message.gas_fee_cap);
        let gas_premium = str_to_token_amount(&message.gas_premium);

        let message_params_bytes =
            base64::decode(&message.params).map_err(|_| Error::InvalidParam)?;
        let params = RawBytes::from(message_params_bytes);
        tcx_ensure!(message.method == 0, Error::InvalidMethodId);

        let tmp = Self {
            version: 0,
            from,
            to,
            sequence: message.nonce,
            value,
            method_num: message.method,
            params,
            gas_limit: gas_limit as u64,
            gas_fee_cap,
            gas_premium,
        };

        Ok(tmp)
    }
}

impl TransactionSigner<UnsignedMessage, SignedMessage> for Keystore {
    fn sign_transaction(
        &mut self,
        sign_context: &SignatureParameters,
        tx: &UnsignedMessage,
    ) -> Result<SignedMessage> {
        let unsigned_message = ForestUnsignedMessage::try_from(tx)?;

        let signature_type;

        let signature;
        let mut cid: Cid = <CidGeneric<64> as CidCborExt>::from_cbor_blake2b256(&unsigned_message)?;
        match sign_context.curve {
            CurveType::SECP256k1 => {
                signature_type = 1;
                signature = self.secp256k1_ecdsa_sign_recoverable(
                    &digest(&cid.to_bytes(), HashSize::Default),
                    &sign_context.derivation_path,
                )?;

                let forest_signed_msg = ForestSignedMessage {
                    message: unsigned_message,
                    signature: ForestSignature {
                        sig_type: SignatureType::Secp256k1,
                        bytes: signature.clone(),
                    },
                };
                cid = <CidGeneric<64> as CidCborExt>::from_cbor_blake2b256(&forest_signed_msg)?;
            }
            CurveType::BLS => {
                signature_type = 2;
                cid = <CidGeneric<64> as CidCborExt>::from_cbor_blake2b256(&unsigned_message)?;
                signature = self.bls_sign(
                    &cid.to_bytes(),
                    &sign_context.derivation_path,
                    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
                )?;
                // use unsigned_message https://github.com/filecoin-project/lotus/issues/101
            }
            _ => return Err(Error::InvalidCurveType.into()),
        }

        Ok(SignedMessage {
            cid: cid.to_string(),
            message: Some(tx.clone()),
            signature: Some(Signature {
                r#type: signature_type,
                data: base64::encode(&signature),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, KeyInfo, UnsignedMessage};
    use tcx_common::{FromHex, ToHex};
    use tcx_constants::CurveType;
    use tcx_keystore::{Keystore, Metadata, SignatureParameters, TransactionSigner};

    #[test]
    fn test_sign_spec256k1() {
        let unsigned_message = UnsignedMessage {
            to: "f1zlkjwo5pnm6petm4u4luj6gb6e64eecrw4t4stq".to_string(),
            from: "f12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
            nonce: 1,
            value: "10000000000000000".to_string(),
            gas_limit: 491585,
            gas_fee_cap: "151367".to_string(),
            gas_premium: "150313".to_string(),
            method: 0,
            params: "".to_string(),
        };

        let key_info =
            KeyInfo::from_lotus(
                &Vec::from_hex("7b2254797065223a22736563703235366b31222c22507269766174654b6579223a222f5059574777574e577a58614d5675437a613958502b314b4a695a4474696f4c76777863754268783041553d227d").unwrap()).unwrap();
        let private_key = key_info.decode_private_key().unwrap();
        let mut ks = Keystore::from_private_key(
            &private_key.to_hex(),
            "Password",
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        ks.unlock_by_password("Password").unwrap();

        let sign_context = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "".to_string(),
            chain_type: "FILECOIN".to_string(),
            ..Default::default()
        };
        let signed_message = ks
            .sign_transaction(&sign_context, &unsigned_message)
            .unwrap();
        let signature = signed_message.signature.unwrap();

        assert_eq!(
            "bafy2bzacec6nqhpi35nwfmdc2two6gs6khs3cgxe7ao2ks6xdwz53qvp2boyu",
            signed_message.cid
        );
        assert_eq!(signature.r#type, 1);
        assert_eq!(signature.data, "MCTI+WjYRozaU/7gYWAwSeOixkSmIHDWHwsU1NVPTrtH4IkXPUrgRcZh4DduJqvHLzoek31LYZxhWkGAzd0j9wA=");
    }

    #[test]
    fn test_invalid_method_id() {
        let unsigned_message = UnsignedMessage {
            to: "f1zlkjwo5pnm6petm4u4luj6gb6e64eecrw4t4stq".to_string(),
            from: "f12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
            nonce: 1,
            value: "10000000000000000".to_string(),
            gas_limit: 491585,
            gas_fee_cap: "151367".to_string(),
            gas_premium: "150313".to_string(),
            method: 1,
            params: "".to_string(),
        };

        let key_info =
            KeyInfo::from_lotus(
                &Vec::from_hex("7b2254797065223a22736563703235366b31222c22507269766174654b6579223a222f5059574777574e577a58614d5675437a613958502b314b4a695a4474696f4c76777863754268783041553d227d").unwrap()).unwrap();
        let private_key = key_info.decode_private_key().unwrap();
        let mut ks = Keystore::from_private_key(
            &private_key.to_hex(),
            "Password",
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        ks.unlock_by_password("Password").unwrap();

        let sign_context = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "".to_string(),
            chain_type: "FILECOIN".to_string(),
            ..Default::default()
        };
        let signed_message = ks.sign_transaction(&sign_context, &unsigned_message);
        assert_eq!(
            format!("{}", signed_message.err().unwrap()),
            "invalid_method_id"
        );
    }

    #[test]
    fn test_sign_bls() {
        let unsigned_message = UnsignedMessage {
            to: "f1zlkjwo5pnm6petm4u4luj6gb6e64eecrw4t4stq".to_string(),
            from: "f3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa".to_string(),
            nonce: 1,
            value: "10000000000000000".to_string(),
            gas_limit: 491585,
            gas_fee_cap: "151367".to_string(),
            gas_premium: "150313".to_string(),
            method: 0,
            params: "".to_string(),
        };

        let key_info =
            KeyInfo::from_lotus(
                &Vec::from_hex("7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d").unwrap()).unwrap();
        let private_key = key_info.decode_private_key().unwrap();
        let mut ks = Keystore::from_private_key(
            &private_key.to_hex(),
            "Password",
            CurveType::BLS,
            Metadata::default(),
            None,
        )
        .unwrap();
        ks.unlock_by_password("Password").unwrap();

        let sign_context = SignatureParameters {
            curve: CurveType::BLS,
            derivation_path: "".to_string(),
            chain_type: "FILECOIN".to_string(),
            ..Default::default()
        };
        let signed_message = ks
            .sign_transaction(&sign_context, &unsigned_message)
            .unwrap();
        let signature = signed_message.signature.unwrap();

        assert_eq!(signature.r#type, 2);
        assert_eq!(
            signed_message.cid,
            "bafy2bzacedbxcjpwgqfkdub732bo5bmtlhudum4fgxdz5ku3e2rziybwm5x5a"
        );
        assert_eq!(signature.data, "tNRsgNdWO6UdY9IOh5tvzcL1Dwi7gljLt22aITKUgtF363lrP2gHxOX9oNGhnFD6BoM4/Y/HMzETlYF0r4+1aHZo1F8fV3XDwxwwz1HKxoDIreXBtPAjTiqBGlTiMwPX");
    }

    #[test]
    fn test_sign_invalid_curve_type() {
        let unsigned_message = UnsignedMessage {
            to: "f1zlkjwo5pnm6petm4u4luj6gb6e64eecrw4t4stq".to_string(),
            from: "f3qdyntx5snnwgmjkp2ztd6tf6hhcmurxfj53zylrqyympwvzvbznx6vnvdqloate5eviphnzrkupno4wheesa".to_string(),
            nonce: 1,
            value: "10000000000000000".to_string(),
            gas_limit: 491585,
            gas_fee_cap: "151367".to_string(),
            gas_premium: "150313".to_string(),
            method: 0,
            params: "".to_string(),
        };

        let key_info =
            KeyInfo::from_lotus(
                &Vec::from_hex("7b2254797065223a22626c73222c22507269766174654b6579223a2269376b4f2b7a78633651532b7637597967636d555968374d55595352657336616e6967694c684b463830383d227d").unwrap()).unwrap();
        let private_key = key_info.decode_private_key().unwrap();
        let mut ks = Keystore::from_private_key(
            &private_key.to_hex(),
            "Password",
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        ks.unlock_by_password("Password").unwrap();

        let sign_context = SignatureParameters {
            curve: CurveType::SR25519,
            derivation_path: "".to_string(),
            chain_type: "FILECOIN".to_string(),
            ..Default::default()
        };
        let actual = ks.sign_transaction(&sign_context, &unsigned_message);
        assert_eq!(
            actual.err().unwrap().to_string(),
            Error::InvalidCurveType.to_string()
        );
    }
}
