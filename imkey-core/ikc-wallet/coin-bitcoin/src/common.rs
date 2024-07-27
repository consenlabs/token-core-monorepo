use crate::transaction::Utxo;
use crate::Result;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::{Address, AddressType, Network, PublicKey};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::error::CoinError;
use ikc_common::utility::{hex_to_bytes, sha256_hash};
use ikc_transport::message::send_apdu;
use secp256k1::{ecdsa::Signature, Message, PublicKey as Secp256k1PublicKey, Secp256k1};
use std::str::FromStr;

/**
utxo address verify
*/
pub fn address_verify(utxos: &Vec<Utxo>, network: Network) -> Result<Vec<String>> {
    let mut utxo_pub_key_vec: Vec<String> = vec![];
    for utxo in utxos {
        let xpub_data = get_xpub_data(&utxo.derive_path, false)?;
        //parsing xpub data
        let derive_pub_key = &xpub_data[..130];
        let chain_code = &xpub_data[130..194];
        let mut extend_public_key = ExtendedPubKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            public_key: Secp256k1PublicKey::from_str(derive_pub_key)?,
            chain_code: ChainCode::from(hex_to_bytes(chain_code)?.as_slice()),
        };

        let public_key = PublicKey::from_str(&extend_public_key.public_key.to_string())?;
        let script_pubkey = utxo.address.script_pubkey();
        let mut se_gen_address = "".to_string();
        if script_pubkey.is_p2pkh() {
            se_gen_address = Address::p2pkh(&public_key, network).to_string();
        } else if script_pubkey.is_p2sh() {
            se_gen_address = Address::p2shwpkh(&public_key, network)?.to_string();
        } else if script_pubkey.is_v0_p2wpkh() {
            se_gen_address = Address::p2wpkh(&public_key, network)?.to_string();
        } else if script_pubkey.is_v1_p2tr() {
            let untweak_pub_key = UntweakedPublicKey::from(secp256k1::PublicKey::from_slice(
                &hex_to_bytes(&derive_pub_key)?,
            )?);
            let secp256k1 = Secp256k1::new();
            se_gen_address = Address::p2tr(&secp256k1, untweak_pub_key, None, network).to_string();
        } else {
            return Err(CoinError::InvalidAddress.into());
        };
        if !se_gen_address.eq(&utxo.address.to_string()) {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        utxo_pub_key_vec.push(extend_public_key.public_key.to_string());
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
            if address.starts_with('1') || address.starts_with('3') {
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
