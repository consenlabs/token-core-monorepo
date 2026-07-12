use crate::common::{get_xpub_data, get_xpub_data_async};
use crate::Result;
use core::result;
use ikc_common::error::CoinError;
use ikc_transport::message::send_apdu;

use bitcoin::address::ParseError as BtcAddressError;
use bitcoin::{Address as BtcAddress, Network, PublicKey, ScriptBuf};
use bitcoincash_addr::{Address as CashAddress, AddressCodec, Base58Codec, CashAddrCodec, Scheme};
use ikc_common::apdu::{Apdu, ApduCheck, BtcApdu};
use ikc_common::constants::BTC_AID;
use ikc_common::path::check_path_validity;
use ikc_common::utility;
use ikc_device::async_device_manager::AsyncApduTransport;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message;

use ikc_common::utility::network_convert;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

fn remove_bch_prefix(addr: &str) -> String {
    if let Some(sep) = addr.rfind(':') {
        if addr.len() > sep + 1 {
            return addr.split_at(sep + 1).1.to_owned();
        }
    }
    addr.to_owned()
}

fn decode_cash_address(addr: &str) -> Result<CashAddress> {
    if let Ok(decoded) = CashAddress::decode(addr) {
        return Ok(decoded);
    }

    if addr.contains(':') {
        return Err(CoinError::InvalidAddress.into());
    }

    for prefix in ["bitcoincash", "bchtest"] {
        let prefixed = format!("{prefix}:{addr}");
        if let Ok(decoded) = CashAddrCodec::decode(&prefixed) {
            return Ok(decoded);
        }
    }

    Err(CoinError::InvalidAddress.into())
}

fn is_legacy_addr(addr: &str) -> bool {
    Base58Codec::decode(addr).is_ok()
}

fn is_cash_addr(addr: &str) -> bool {
    !is_legacy_addr(addr) && decode_cash_address(addr).is_ok()
}

fn legacy_to_bch(addr: &str) -> Result<String> {
    let bch_addr = if let Ok(mut decoded) = Base58Codec::decode(addr) {
        decoded.scheme = Scheme::CashAddr;
        decoded
            .encode()
            .map_err(|_| CoinError::ConvertToCashAddressFailed)?
    } else {
        addr.to_string()
    };
    Ok(remove_bch_prefix(&bch_addr))
}

fn bch_to_legacy(addr: &str) -> Result<String> {
    if is_legacy_addr(addr) {
        Ok(addr.to_string())
    } else {
        let mut decoded = decode_cash_address(addr)?;
        decoded.scheme = Scheme::Base58;
        decoded
            .encode()
            .map_err(|_| CoinError::ConvertToLegacyAddressFailed.into())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BchAddress(pub BtcAddress);

impl BchAddress {
    pub fn convert_to_legacy_if_need(addr: &str) -> Result<String> {
        if is_cash_addr(addr) {
            bch_to_legacy(addr)
        } else {
            Ok(addr.to_string())
        }
    }

    pub fn get_pub_key(_network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(BTC_AID)?;
        let select_response = message::send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        //get xpub data
        let res_msg_pubkey = get_xpub_data(path, true)?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];
        let key_manager_obj = KEY_MANAGER.lock();
        let sign_verify_result = utility::secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            hex::decode(sign_source_val).unwrap().as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let uncomprs_pubkey: String = res_msg_pubkey.chars().take(130).collect();
        Ok(uncomprs_pubkey)
    }

    pub async fn get_pub_key_async<T>(
        transport: &T,
        _network: Network,
        path: &str,
    ) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(BTC_AID)?;
        let select_response = transport.send_apdu(&select_apdu, 20).await?;
        ApduCheck::check_response(&select_response)?;

        let res_msg_pubkey = get_xpub_data_async(transport, path, true).await?;

        let sign_source_val = &res_msg_pubkey[..194];
        let sign_result = &res_msg_pubkey[194..res_msg_pubkey.len() - 4];
        let se_pub_key = {
            let key_manager_obj = KEY_MANAGER.lock();
            key_manager_obj.se_pub_key.clone()
        };
        let sign_verify_result = utility::secp256k1_sign_verify(
            &se_pub_key,
            hex::decode(sign_result)?.as_slice(),
            hex::decode(sign_source_val)?.as_slice(),
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        let uncomprs_pubkey: String = res_msg_pubkey.chars().take(130).collect();
        Ok(uncomprs_pubkey)
    }

    /**
    get btc address by path
    */
    pub fn get_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get pub key
        let pub_key = Self::get_pub_key(network, path)?;
        let mut pub_key_obj = PublicKey::from_str(&pub_key)?;
        pub_key_obj.compressed = true;
        let addr = BtcAddress::p2pkh(pub_key_obj, network).to_string();
        legacy_to_bch(&addr)
    }

    pub async fn get_address_async<T>(transport: &T, network: Network, path: &str) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        check_path_validity(path)?;

        let pub_key = Self::get_pub_key_async(transport, network, path).await?;
        let mut pub_key_obj = PublicKey::from_str(&pub_key)?;
        pub_key_obj.compressed = true;
        let addr = BtcAddress::p2pkh(pub_key_obj, network).to_string();
        legacy_to_bch(&addr)
    }

    pub fn display_address(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;
        let address_str = Self::get_address(network, path)?;
        let apdu_res = send_apdu(BtcApdu::register_name_address(
            "BCH".as_bytes(),
            &address_str.clone().into_bytes().to_vec(),
        )?)?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address_str)
    }

    pub async fn display_address_async<T>(
        transport: &T,
        network: Network,
        path: &str,
    ) -> Result<String>
    where
        T: AsyncApduTransport + ?Sized,
    {
        check_path_validity(path)?;
        let address_str = Self::get_address_async(transport, network, path).await?;
        let apdu = BtcApdu::register_name_address(
            "BCH".as_bytes(),
            &address_str.clone().into_bytes().to_vec(),
        )?;
        let response = transport.send_apdu(&apdu, 20).await?;
        ApduCheck::check_response(response.as_str())?;
        Ok(address_str)
    }

    pub fn script_pubkey(target_addr: &str) -> Result<ScriptBuf> {
        let target_addr = BchAddress::convert_to_legacy_if_need(target_addr)?;
        let addr = BtcAddress::from_str(&target_addr)?;
        Ok(addr.assume_checked().script_pubkey())
    }

    pub fn is_valid(address: &str) -> bool {
        is_legacy_addr(address) || decode_cash_address(address).is_ok()
    }

    pub fn from_pub_key(pub_key: &[u8], network: &str) -> Result<String> {
        let network = network_convert(network);
        let mut pub_key_obj = PublicKey::from_slice(pub_key)?;
        pub_key_obj.compressed = true;
        let addr = BtcAddress::p2pkh(pub_key_obj, network).to_string();
        legacy_to_bch(&addr)
    }
}

impl FromStr for BchAddress {
    type Err = BtcAddressError;
    fn from_str(s: &str) -> result::Result<BchAddress, BtcAddressError> {
        let legacy = bch_to_legacy(s).expect("_bch_to_legacy");
        let btc_addr = BtcAddress::from_str(&legacy)?;
        Ok(BchAddress(btc_addr.assume_checked()))
    }
}

impl Display for BchAddress {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let legacy = self.0.to_string();
        let baddr = legacy_to_bch(&legacy).expect("legacy_to_bch");
        std::fmt::Display::fmt(&baddr, f)
    }
}

#[cfg(test)]
mod tests {
    use crate::address::BchAddress;
    use bitcoin::Network;
    use ikc_device::device_binding::bind_test;

    #[test]
    pub fn test_convert() {
        assert_eq!(
            BchAddress::convert_to_legacy_if_need("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf").unwrap(),
            "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf"
        );
        assert_eq!(
            BchAddress::convert_to_legacy_if_need("qqyta3mqzeaxe8hqcdsgpy4srwd4f0fc0gj0njf885")
                .unwrap(),
            "1oEx5Ztg2DUDYJDxb1AeaiG5TYesikMVU"
        );
    }

    #[test]
    fn is_valid_accepts_legacy_and_cash_addresses() {
        assert!(BchAddress::is_valid("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf"));
        assert!(BchAddress::is_valid(
            "qqyta3mqzeaxe8hqcdsgpy4srwd4f0fc0gj0njf885"
        ));
        assert!(BchAddress::is_valid(
            "bitcoincash:qqyta3mqzeaxe8hqcdsgpy4srwd4f0fc0gj0njf885"
        ));
        assert!(!BchAddress::is_valid("not-a-bch-address"));
    }

    #[test]
    fn get_address_test() {
        bind_test();

        let network: Network = Network::Bitcoin;
        let path: &str = "m/44'/145'/0'/0/0";
        let get_btc_address_result = BchAddress::get_address(network, path);

        assert!(get_btc_address_result.is_ok());
        let btc_address = get_btc_address_result.ok().unwrap();
        assert_eq!("qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r", btc_address);

        let network: Network = Network::Bitcoin;
        let path: &str = "m/44'/145'/0'/1/0";
        let get_btc_address_result = BchAddress::get_address(network, path);

        assert!(get_btc_address_result.is_ok());
        let btc_address = get_btc_address_result.ok().unwrap();
        assert_eq!("qq5jyy9vmsznss93gmt8m2v2fep7wvpdwsn2hrjgsg", btc_address);

        let network: Network = Network::Testnet;
        let path: &str = "m/44'/145'/0'/0/0";
        let get_btc_address_result = BchAddress::get_address(network, path);

        assert!(get_btc_address_result.is_ok());
        let btc_address = get_btc_address_result.ok().unwrap();
        assert_eq!("qzld7dav7d2sfjdl6x9snkvf6raj8lfxjckxd69ndl", btc_address);
    }

    #[test]
    fn display_address_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/145'/0'/0/0";
        let get_btc_address_result = BchAddress::display_address(version, path);

        assert!(get_btc_address_result.is_ok());
        let btc_address = get_btc_address_result.ok().unwrap();
        assert_eq!("qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r", btc_address);
    }
}
