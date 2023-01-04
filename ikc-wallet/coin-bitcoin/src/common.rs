use crate::transaction::Utxo;
use crate::Result;
use bitcoin::secp256k1::Secp256k1 as BitcoinSecp256k1;
use bitcoin::util::base58;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::{Address, Network, PublicKey};
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::constants::{
    BTC_LEGACY_MAINNET_PATH, BTC_LEGACY_TESTNET_PATH, BTC_NATIVE_SEGWIT_MAINNET_PATH,
    BTC_NATIVE_SEGWIT_TESTNET_PATH, BTC_SEGWIT_MAINNET_PATH, BTC_SEGWIT_TESTNET_PATH,
    UNCOMPRESSED_PUBKEY_STRING_LEN, XPUB_STRING_LEN,
};
use ikc_common::error::CoinError;
use ikc_common::utility::sha256_hash;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;
use secp256k1::{Message, PublicKey as Secp256k1PublicKey, Secp256k1, Signature};
use std::collections::HashMap;
use std::str::FromStr;

/**
utxo address verify
*/
pub fn address_verify(
    utxos: &Vec<Utxo>,
    public_key: &str,
    chain_code: &[u8],
    network: Network,
    trans_type_flg: TransTypeFlg,
) -> Result<Vec<String>> {
    let mut utxo_pub_key_vec: Vec<String> = vec![];
    for utxo in utxos {
        //get utxo public key
        let public_key_obj = Secp256k1PublicKey::from_str(public_key)?;
        //gen chain code obj
        let chain_code_obj = ChainCode::from(chain_code);
        //build extended public key
        let mut extend_public_key = ExtendedPubKey {
            network: network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            public_key: public_key_obj,
            chain_code: chain_code_obj,
        };

        let bitcoin_secp = BitcoinSecp256k1::new();
        let index_number_vec: Vec<&str> = utxo.derive_path.as_str().split('/').collect();
        for index_number in index_number_vec {
            let test_chain_number = ChildNumber::from_normal_idx(index_number.parse().unwrap())?;
            extend_public_key = extend_public_key.ckd_pub(&bitcoin_secp, test_chain_number)?;
        }
        //verify address
        let se_gen_address: Result<String> = match trans_type_flg {
            TransTypeFlg::BTC => Ok(Address::p2pkh(
                &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
                network,
            )
            .to_string()),
            TransTypeFlg::SEGWIT => Ok(Address::p2shwpkh(
                &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
                network,
            )?
            .to_string()),
            TransTypeFlg::NATIVE => Ok(Address::p2wpkh(
                &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
                network,
            )?
            .to_string()),
        };
        let se_gen_address_str = se_gen_address?;
        let utxo_address = utxo.address.to_string();
        if !se_gen_address_str.eq(&utxo_address) {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }
        utxo_pub_key_vec.push(extend_public_key.public_key.to_string());
    }
    Ok(utxo_pub_key_vec)
}

pub struct PathPubKey {
    pub path: String,
    pub pub_key: String,
}

pub fn get_path_and_pubkeys(utxos: &Vec<Utxo>, network: Network) -> Result<Vec<PathPubKey>> {
    let mut path_and_pubkeys: Vec<PathPubKey> = vec![];
    let mut parent_path_and_pubkeys: HashMap<String, String> = HashMap::new();
    for utxo in utxos {
        let parent_path = &get_parent_path(utxo, network)?;
        let trans_type_flg = get_trans_type_flg(utxo)?;

        // Obtain the parent path xpub
        let parent: Result<String> = match parent_path_and_pubkeys.get(parent_path) {
            Some(xpub) => Ok(xpub.to_string()),
            None => {
                let xpub = get_xpub_safe(parent_path, true)?;
                parent_path_and_pubkeys.insert(parent_path.to_string(), xpub.clone());
                Ok(xpub)
            }
        };

        let parent_xpub = parent.unwrap();
        let pub_key = &parent_xpub[..UNCOMPRESSED_PUBKEY_STRING_LEN];
        let chain_code = &parent_xpub[UNCOMPRESSED_PUBKEY_STRING_LEN..];

        let extend_public_key = derive_child_key(utxo, network, pub_key, chain_code)?;

        //verify address
        let result = verify_address(utxo, network, trans_type_flg, extend_public_key)?;
        if !result {
            return Err(CoinError::ImkeyAddressMismatchWithPath.into());
        }

        let path = format!("{}/{}", parent_path, utxo.derive_path);
        let path_pub_key = PathPubKey {
            path,
            pub_key: extend_public_key.public_key.to_string(),
        };
        path_and_pubkeys.push(path_pub_key);
    }
    Ok(path_and_pubkeys)
}

/**
Transaction type identification
*/
pub enum TransTypeFlg {
    BTC,
    SEGWIT,
    NATIVE,
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

pub fn get_xpub_safe(path: &str, verify_flag: bool) -> Result<String> {
    let select_response = send_apdu(BtcApdu::select_applet())?;
    ApduCheck::check_response(&select_response)?;
    let xpub_data = send_apdu(BtcApdu::get_xpub(path, verify_flag))?;
    ApduCheck::check_response(&xpub_data)?;

    let xpub_data = &xpub_data[..xpub_data.len() - 4].to_string();

    //parsing xpub data
    let sign_source_val = &xpub_data[..XPUB_STRING_LEN];
    let sign_result = &xpub_data[XPUB_STRING_LEN..];

    //use se public key verify sign
    let key_manager_obj = KEY_MANAGER.lock();
    let sign_verify_result = secp256k1_sign_verify(
        &key_manager_obj.se_pub_key.as_slice(),
        hex::decode(sign_result).unwrap().as_slice(),
        hex::decode(sign_source_val).unwrap().as_slice(),
    );
    if sign_verify_result.is_err() || !sign_verify_result.ok().unwrap() {
        return Err(CoinError::ImkeySignatureVerifyFail.into());
    }

    Ok(sign_source_val.to_string())
}

pub fn get_parent_path(utxo: &Utxo, network: Network) -> Result<String> {
    // legacy
    if utxo.script_pubkey.starts_with("76a914") || utxo.script_pubkey.starts_with("76A914") {
        if network.clone() == Network::Testnet {
            Ok(BTC_LEGACY_TESTNET_PATH.to_string())
        } else {
            Ok(BTC_LEGACY_MAINNET_PATH.to_string())
        }
        // segwit
    } else if utxo.script_pubkey.starts_with("a914") || utxo.script_pubkey.starts_with("A914") {
        if network.clone() == Network::Testnet {
            Ok(BTC_SEGWIT_TESTNET_PATH.to_string())
        } else {
            Ok(BTC_SEGWIT_MAINNET_PATH.to_string())
        }
    } else if utxo.script_pubkey.starts_with("0014") {
        if network.clone() == Network::Testnet {
            Ok(BTC_NATIVE_SEGWIT_TESTNET_PATH.to_string())
        } else {
            Ok(BTC_NATIVE_SEGWIT_MAINNET_PATH.to_string())
        }
    } else {
        return Err(CoinError::UnsupportedScriptPubkey.into());
    }
}

pub fn get_trans_type_flg(utxo: &Utxo) -> Result<TransTypeFlg> {
    // legacy
    if utxo.script_pubkey.starts_with("76a914") || utxo.script_pubkey.starts_with("76A914") {
        Ok(TransTypeFlg::BTC)
        // segwit
    } else if utxo.script_pubkey.starts_with("a914") || utxo.script_pubkey.starts_with("A914") {
        Ok(TransTypeFlg::SEGWIT)
    } else if utxo.script_pubkey.starts_with("0014") {
        Ok(TransTypeFlg::NATIVE)
    } else {
        return Err(CoinError::UnsupportedScriptPubkey.into());
    }
}

// Public child key derivation
pub fn derive_child_key(
    utxo: &Utxo,
    network: Network,
    pub_key: &str,
    chain_code: &str,
) -> Result<ExtendedPubKey> {
    //get utxo public key
    let mut public_key_obj = Secp256k1PublicKey::from_str(pub_key)?;
    //gen chain code obj
    let chain_code_obj = ChainCode::from(hex::decode(chain_code).unwrap().as_slice());
    //build extended public key
    let mut extend_public_key = ExtendedPubKey {
        network: network,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::from_normal_idx(0)?,
        public_key: public_key_obj,
        chain_code: chain_code_obj,
    };

    let bitcoin_secp = BitcoinSecp256k1::new();
    let index_number_vec: Vec<&str> = utxo.derive_path.as_str().split('/').collect();
    for index_number in index_number_vec {
        let test_chain_number = ChildNumber::from_normal_idx(index_number.parse().unwrap())?;
        extend_public_key = extend_public_key.ckd_pub(&bitcoin_secp, test_chain_number)?;
    }
    Ok(extend_public_key)
}

pub fn verify_address(
    utxo: &Utxo,
    network: Network,
    trans_type_flg: TransTypeFlg,
    extend_public_key: ExtendedPubKey,
) -> Result<bool> {
    let se_gen_address: Result<String> = match trans_type_flg {
        TransTypeFlg::BTC => Ok(Address::p2pkh(
            &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
            network,
        )
        .to_string()),
        TransTypeFlg::SEGWIT => Ok(Address::p2shwpkh(
            &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
            network,
        )?
        .to_string()),
        TransTypeFlg::NATIVE => Ok(Address::p2wpkh(
            &PublicKey::from_str(extend_public_key.public_key.to_string().as_str())?,
            network,
        )?
        .to_string()),
    };

    let se_gen_address_str = se_gen_address?;
    let utxo_address = utxo.address.to_string();
    if se_gen_address_str.eq(&utxo_address) {
        Ok(true)
    } else {
        Ok(false)
    }
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
    Ok(secp.verify(&message_obj, &sig_obj, &public_obj).is_ok())
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
                return Err(CoinError::AddressTypeMismatch.into());
            }
        }
        Network::Testnet => {
            if address.starts_with('m') || address.starts_with('n') || address.starts_with('2') {
                let address_bytes = base58::from(address)?;
                address_bytes.as_slice()[0]
            } else if address.starts_with("tb1") {
                't' as u8
            } else {
                return Err(CoinError::AddressTypeMismatch.into());
            }
        }
        _ => {
            return Err(CoinError::ImkeySdkIllegalArgument.into());
        }
    };
    //get address version
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
    use crate::transaction::Utxo;
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
