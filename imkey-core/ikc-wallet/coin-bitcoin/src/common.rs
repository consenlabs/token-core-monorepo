use crate::transaction::Utxo;
use crate::Result;
use bitcoin::util::base58;
use bitcoin::{Network, PublicKey};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::sha256_hash;
use ikc_transport::message::send_apdu;
use secp256k1::{ecdsa::Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1};
use std::str::FromStr;

/**
get utxo public key
*/
pub fn get_utxo_pub_key(utxos: &Vec<Utxo>) -> Result<Vec<String>> {
    let mut utxo_pub_key_vec: Vec<String> = vec![];
    for utxo in utxos {
        let xpub_data = get_xpub_data(&utxo.derive_path, true)?;
        //parsing xpub data
        let derive_pub_key = public_key_from_xpub_response(&xpub_data)?;

        let mut public_key = PublicKey::from_str(derive_pub_key)?;
        public_key.compressed = true;

        let script = bitcoin::Script::from_str(&utxo.script_pubkey)?;
        validate_script_key(&script, &public_key)?;
        utxo_pub_key_vec.push(public_key.to_string());
    }
    Ok(utxo_pub_key_vec)
}

/**
get xpub
*/
pub fn get_xpub_data(path: &str, verify_flag: bool) -> Result<String> {
    let select_response = send_apdu(BtcApdu::select_applet())?;
    ApduCheck::check_response(&select_response)?;
    let xpub_data = send_apdu(BtcApdu::get_xpub(path, verify_flag))?;
    ApduCheck::check_response(&xpub_data)?;
    if verify_flag {
        let se_pubkey = ikc_device::device_binding::KEY_MANAGER
            .lock()
            .se_pub_key
            .clone();
        verify_xpub_response(&xpub_data, &se_pubkey)?;
    }
    Ok(xpub_data)
}

/**
select btc applet
 */
pub fn select_btc_applet() -> Result<()> {
    let select_response = send_apdu(BtcApdu::select_applet())?;
    ApduCheck::check_response(&select_response)?;
    Ok(())
}

/**
sign verify
*/
pub fn secp256k1_sign_verify(public: &[u8], signed: &[u8], message: &[u8]) -> Result<bool> {
    let secp = Secp256k1::new();
    //build public
    let public_obj = Secp256k1PublicKey::from_slice(public)?;
    //build message
    let hash_result = sha256_hash(message);
    let message_obj = Message::from_slice(hash_result.as_ref())?;
    //build signature obj
    let mut sig_obj = Signature::from_der(signed)?;
    sig_obj.normalize_s();
    //verify
    Ok(secp
        .verify_ecdsa(&message_obj, &sig_obj, &public_obj)
        .is_ok())
}

/**
get address version
*/
pub fn get_address_version(network: Network, address: &str) -> Result<u8> {
    let version = match network {
        Network::Bitcoin => {
            if address.starts_with('1')
                || address.starts_with('3')
                || address.starts_with('D')
                || address.starts_with('A')
            {
                let address_bytes = base58::from(address)?;
                address_bytes.as_slice()[0]
            } else if address.starts_with("bc1") {
                'b' as u8
            } else {
                return Err(CoinError::InvalidAddress.into());
            }
        }
        Network::Testnet => {
            if address.starts_with('m') || address.starts_with('n') || address.starts_with('2') {
                let address_bytes = base58::from(address)?;
                address_bytes.as_slice()[0]
            } else if address.starts_with("tb1") {
                't' as u8
            } else {
                return Err(CoinError::InvalidAddress.into());
            }
        }
        _ => {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }
    };
    Ok(version)
}

pub struct TxSignResult {
    pub signature: String,
    pub tx_hash: String,
    pub wtx_id: String,
}

#[cfg(test)]
mod test {
    use crate::common::get_address_version;
    use bitcoin::Network;

    #[test]
    fn get_address_version_test() {
        let address_version =
            get_address_version(Network::Bitcoin, "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt");
        assert!(address_version.is_ok());
        assert_eq!(5, address_version.ok().unwrap());

        let address_version =
            get_address_version(Network::Bitcoin, "2CVD68V71no5jn2UZpLLq6hASpXu1jrByt");
        assert_eq!(
            format!("{}", address_version.err().unwrap()),
            "address_type_mismatch"
        );

        let address_version =
            get_address_version(Network::Testnet, "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt");
        assert_eq!(
            format!("{}", address_version.err().unwrap()),
            "address_type_mismatch"
        );

        let address_version =
            get_address_version(Network::Regtest, "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt");
        assert_eq!(
            format!("{}", address_version.err().unwrap()),
            "imkey_sdk_illegal_argument"
        );
    }
}

pub fn public_key_from_xpub_response(xpub_data: &str) -> Result<&str> {
    xpub_data
        .get(..130)
        .ok_or_else(|| CoinError::GetXpubError.into())
}

pub(crate) fn validate_script_key(script: &bitcoin::Script, key: &PublicKey) -> Result<()> {
    use bitcoin::{schnorr::TapTweak, Script};
    let witness = Script::new_v0_p2wpkh(&key.wpubkey_hash().ok_or(CoinError::InvalidParam)?);
    let expected = if script.is_p2pkh() {
        Script::new_p2pkh(&key.pubkey_hash())
    } else if script.is_p2sh() {
        witness.to_p2sh()
    } else if script.is_v0_p2wpkh() {
        witness
    } else if script.is_v1_p2tr() {
        let (internal_key, _) = key.inner.x_only_public_key();
        let (output_key, _) = internal_key.tap_tweak(&Secp256k1::verification_only(), None);
        Script::new_v1_p2tr_tweaked(output_key)
    } else {
        return Err(CoinError::InvalidUtxo.into());
    };
    if script != &expected {
        return Err(CoinError::ImkeyAddressMismatchWithPath.into());
    }
    Ok(())
}

pub(crate) fn verify_xpub_response(response: &str, se_pubkey: &[u8]) -> Result<()> {
    let checked = || -> Result<bool> {
        let end = response
            .len()
            .checked_sub(4)
            .ok_or(CoinError::GetXpubError)?;
        let source = response.get(..194).ok_or(CoinError::GetXpubError)?;
        let signature = response.get(194..end).ok_or(CoinError::GetXpubError)?;
        secp256k1_sign_verify(se_pubkey, &hex::decode(signature)?, &hex::decode(source)?)
    };
    if checked().unwrap_or(false) {
        Ok(())
    } else {
        Err(CoinError::ImkeySignatureVerifyFail.into())
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn security_xpub_requires_valid_se_signature() {
        let secp = Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[9; 32]).unwrap();
        let trusted = Secp256k1PublicKey::from_secret_key(&secp, &secret);
        let public = Secp256k1PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
        );
        let mut source = public.serialize_uncompressed().to_vec();
        source.extend([0u8; 32]);
        let digest = sha256_hash(&source);
        let signature = secp
            .sign_ecdsa(&Message::from_slice(&digest).unwrap(), &secret)
            .serialize_der();
        let response = format!("{}{}9000", hex::encode(&source), hex::encode(signature));
        assert!(verify_xpub_response(&response, &trusted.serialize()).is_ok());
        assert!(verify_xpub_response(
            &format!("{}9000", hex::encode(&source)),
            &trusted.serialize()
        )
        .is_err());
        let mut forged = source.clone();
        forged[65] ^= 1;
        assert!(verify_xpub_response(
            &format!("{}{}9000", hex::encode(forged), hex::encode(signature)),
            &trusted.serialize()
        )
        .is_err());
        for short in ["", "9000", "049000", "invalid9000"] {
            assert!(verify_xpub_response(short, &trusted.serialize()).is_err());
        }
    }
}
