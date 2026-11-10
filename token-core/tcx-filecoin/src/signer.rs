use crate::transaction::{Signature, SignedMessage, UnsignedMessage};
use crate::utils::{digest, HashSize};
use crate::Error;
use anyhow::anyhow;
use forest_address::Address;
use forest_cid::{self, Cid, Code};
use forest_encoding::{ser, serde_bytes, to_vec};
use forest_vm::{Serialized, TokenAmount};
use num_bigint_chainsafe::bigint_ser::BigIntSer;
use std::convert::TryFrom;
use std::str::FromStr;
use tcx_constants::CurveType;
use tcx_keystore::{tcx_ensure, Keystore, Result, SignatureParameters, Signer, TransactionSigner};

struct FilecoinUnsignedMessage {
    version: i64,
    from: Address,
    to: Address,
    sequence: u64,
    value: TokenAmount,
    method_num: u64,
    params: Serialized,
    gas_limit: i64,
    gas_fee_cap: TokenAmount,
    gas_premium: TokenAmount,
}

impl ser::Serialize for FilecoinUnsignedMessage {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ser::Serialize::serialize(
            &(
                &self.version,
                &self.to,
                &self.from,
                &self.sequence,
                BigIntSer(&self.value),
                &self.gas_limit,
                BigIntSer(&self.gas_fee_cap),
                BigIntSer(&self.gas_premium),
                &self.method_num,
                &self.params,
            ),
            serializer,
        )
    }
}

struct Secp256k1SignedMessage<'a> {
    message: &'a FilecoinUnsignedMessage,
    signature: Secp256k1Signature<'a>,
}

impl ser::Serialize for Secp256k1SignedMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ser::Serialize::serialize(&(&self.message, &self.signature), serializer)
    }
}

struct Secp256k1Signature<'a>(&'a [u8]);

impl ser::Serialize for Secp256k1Signature<'_> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut bytes = Vec::with_capacity(self.0.len() + 1);
        bytes.push(1);
        bytes.extend_from_slice(self.0);
        serde_bytes::Serialize::serialize(&bytes, serializer)
    }
}

fn secp256k1_signed_message_cid(
    message: &FilecoinUnsignedMessage,
    signature: &[u8],
) -> core::result::Result<Cid, forest_encoding::Error> {
    let signed_message = Secp256k1SignedMessage {
        message,
        signature: Secp256k1Signature(signature),
    };
    Ok(forest_cid::new_from_cbor(
        &to_vec(&signed_message)?,
        Code::Blake2b256,
    ))
}

fn unsigned_message_cid(
    message: &FilecoinUnsignedMessage,
) -> core::result::Result<Cid, forest_encoding::Error> {
    Ok(forest_cid::new_from_cbor(
        &to_vec(message)?,
        Code::Blake2b256,
    ))
}

impl TryFrom<&UnsignedMessage> for FilecoinUnsignedMessage {
    type Error = crate::Error;

    fn try_from(
        message: &UnsignedMessage,
    ) -> core::result::Result<FilecoinUnsignedMessage, Self::Error> {
        let to = Address::from_str(&message.to).map_err(|_| Error::InvalidAddress)?;
        let from = Address::from_str(&message.from).map_err(|_| Error::InvalidAddress)?;
        let value = TokenAmount::from_str(&message.value).map_err(|_| Error::InvalidNumber)?;
        let gas_limit = message.gas_limit;
        let gas_fee_cap =
            TokenAmount::from_str(&message.gas_fee_cap).map_err(|_| Error::InvalidNumber)?;
        let gas_premium =
            TokenAmount::from_str(&message.gas_premium).map_err(|_| Error::InvalidNumber)?;

        let message_params_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &message.params)
                .map_err(|_| Error::InvalidParam)?;
        let params = Serialized::new(message_params_bytes);
        tcx_ensure!(message.method == 0, Error::InvalidMethodId);

        Ok(FilecoinUnsignedMessage {
            version: 0,
            to,
            from,
            sequence: message.nonce,
            value,
            method_num: message.method,
            params,
            gas_limit,
            gas_premium,
            gas_fee_cap,
        })
    }
}

impl TransactionSigner<UnsignedMessage, SignedMessage> for Keystore {
    fn sign_transaction(
        &mut self,
        sign_context: &SignatureParameters,
        tx: &UnsignedMessage,
    ) -> Result<SignedMessage> {
        let unsigned_message = FilecoinUnsignedMessage::try_from(tx)?;

        let signature_type;

        let signature;
        let mut cid: Cid = unsigned_message_cid(&unsigned_message)?;
        match sign_context.curve {
            CurveType::SECP256k1 => {
                signature_type = 1;
                signature = self.secp256k1_ecdsa_sign_recoverable(
                    &digest(&cid.to_bytes(), HashSize::Default),
                    &sign_context.derivation_path,
                )?;

                cid = secp256k1_signed_message_cid(&unsigned_message, &signature)
                    .map_err(|_e| anyhow!("{}", "forest_message cid error"))?;
            }
            CurveType::BLS => {
                signature_type = 2;
                signature = self.bls_sign(
                    &cid.to_bytes(),
                    &sign_context.derivation_path,
                    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
                )?;
                // use unsigned_message https://github.com/filecoin-project/lotus/issues/101
                cid = unsigned_message_cid(&unsigned_message)?;
            }
            _ => return Err(Error::InvalidCurveType.into()),
        }

        Ok(SignedMessage {
            cid: cid.to_string(),
            message: Some(tx.clone()),
            signature: Some(Signature {
                r#type: signature_type,
                data: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &signature,
                ),
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
            params: "".to_string()
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
            params: "".to_string()
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
