use crate::address::{BtcKinAddress, ScriptPubkey};
use crate::{Error, Result};

use bch_addr::Converter;
use bitcoin::Script;

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::CoinInfo;
use tcx_keystore::Address;
use tcx_primitive::TypedPublicKey;

fn remove_bch_prefix(addr: &str) -> String {
    if let Some(sep) = addr.rfind(':') {
        if addr.len() > sep + 1 {
            return addr.split_at(sep + 1).1.to_owned();
        }
    }
    addr.to_owned()
}

fn legacy_to_bch(addr: &str) -> Result<String> {
    let convert = Converter::new();
    let bch_addr = if convert.is_legacy_addr(addr) {
        convert
            .to_cash_addr(addr)
            .map_err(|_| Error::ConvertToCashAddressFailed(addr.to_string()))?
    } else {
        addr.to_string()
    };
    Ok(remove_bch_prefix(&bch_addr))
}

fn bch_to_legacy(addr: &str) -> Result<String> {
    let convert = Converter::new();
    if !convert.is_legacy_addr(addr) {
        Ok(convert
            .to_legacy_addr(addr)
            .map_err(|_| Error::InvalidAddress)?)
    } else {
        Ok(addr.to_string())
    }
}

impl FromStr for BchAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<BchAddress> {
        let legacy = bch_to_legacy(s)?;
        let btc_addr = BtcKinAddress::from_str(&legacy)?;
        Ok(BchAddress(btc_addr))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BchAddress(pub BtcKinAddress);

impl BchAddress {
    pub fn convert_to_legacy_if_need(addr: &str) -> Result<String> {
        if Converter::default().is_cash_addr(addr) {
            bch_to_legacy(addr)
        } else {
            Ok(addr.to_string())
        }
    }
}

impl Address for BchAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        Ok(BchAddress(BtcKinAddress::from_public_key(
            public_key, coin,
        )?))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let converter = Converter::default();

        if converter.is_legacy_addr(address) || converter.is_cash_addr(address) {
            if converter.is_mainnet_addr(address) {
                coin.network == "MAINNET"
            } else {
                coin.network == "TESTNET"
            }
        } else {
            false
        }
    }
}

impl Display for BchAddress {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let legacy = self.0.to_string();
        let baddr = legacy_to_bch(&legacy).expect("legacy_to_bch");
        std::fmt::Display::fmt(&baddr, f)
    }
}

impl ScriptPubkey for BchAddress {
    fn script_pubkey(&self) -> Script {
        self.0.script_pubkey()
    }
}

#[cfg(test)]
mod tests {
    use super::{remove_bch_prefix, BchAddress};
    use tcx_common::FromHex;

    use crate::address::WIFDisplay;
    use crate::BtcKinAddress;
    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::Address;
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, TypedPublicKey};
    use tcx_primitive::{PublicKey, TypedPrivateKey};

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
    pub fn test_from_pub_key() {
        let coin_info = coin_info_from_param("BITCOINCASH", "MAINNET", "NONE", "").unwrap();
        let addr = BchAddress::from_public_key(
            &TypedPublicKey::from_slice(
                CurveType::SECP256k1,
                &Vec::from_hex(
                    "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
                )
                .unwrap(),
            )
            .unwrap(),
            &coin_info,
        )
        .unwrap();
        assert_eq!(
            format!("{}", addr),
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"
        );

        let coin_info = coin_info_from_param("BITCOINCASH", "TESTNET", "NONE", "").unwrap();
        let addr = BchAddress::from_public_key(
            &TypedPublicKey::from_slice(
                CurveType::SECP256k1,
                &Vec::from_hex(
                    "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
                )
                .unwrap(),
            )
            .unwrap(),
            &coin_info,
        )
        .unwrap();
        assert_eq!(
            format!("{}", addr),
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuqfkeunuc"
        );

        let coin_info = coin_info_from_param("BITCOINCASH", "MAINNET", "NONE", "").unwrap();
        let sk =
            Secp256k1PrivateKey::from_wif("L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy")
                .unwrap();
        let pk =
            TypedPublicKey::from_slice(CurveType::SECP256k1, &sk.public_key().to_bytes()).unwrap();
        let addr = BchAddress::from_public_key(&pk, &coin_info).unwrap();
        assert_eq!(
            format!("{}", addr),
            "qprcvtlpvhnpyxhcp4wau8ktg78dzuzktvetlc7g9s"
        );

        let coin_info = coin_info_from_param("BITCOINCASH", "TESTNET", "NONE", "").unwrap();
        let sk =
            Secp256k1PrivateKey::from_wif("cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG")
                .unwrap();
        let pk =
            TypedPublicKey::from_slice(CurveType::SECP256k1, &sk.public_key().to_bytes()).unwrap();
        let addr = BchAddress::from_public_key(&pk, &coin_info).unwrap();
        assert_eq!(
            format!("{}", addr),
            "qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8"
        );

        let wrong_coin_info = CoinInfo {
            coin: "BITCOINCASH".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let ret = BchAddress::from_public_key(&pk, &wrong_coin_info);
        assert_eq!(format!("{}", ret.err().unwrap()), "missing_network");
    }

    #[test]
    pub fn empty_prefix() {
        assert_eq!(
            remove_bch_prefix("bchtest:qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8"),
            "qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8"
        );
        assert_eq!(
            remove_bch_prefix("qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"),
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"
        );
        assert_eq!(remove_bch_prefix("bitcoincash:"), "bitcoincash:");
        assert_eq!(
            remove_bch_prefix("qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"),
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"
        );
        assert_eq!(
            remove_bch_prefix(":qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"),
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy"
        );
    }

    #[test]
    pub fn address_valid_test() {
        let coin_info = coin_info_from_param("BITCOINCASH", "MAINNET", "NONE", "").unwrap();
        assert!(BchAddress::is_valid(
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ymy",
            &coin_info
        ));
        let coin_info = coin_info_from_param("BITCOINCASH", "TESTNET", "NONE", "").unwrap();
        assert!(BchAddress::is_valid(
            "bchtest:qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8",
            &coin_info
        ));
        assert!(BchAddress::is_valid(
            "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf",
            &coin_info
        ));

        let coin_info = coin_info_from_param("BITCOINCASH", "MAINNET", "NONE", "").unwrap();
        assert!(!BchAddress::is_valid(
            "qq2ug6v04ht22n0daxxzl0rzlvsmzwcdwuymj77ym",
            &coin_info
        ));
        assert!(!BchAddress::is_valid("1234", &coin_info));
    }

    #[test]
    pub fn test_wif_display() {
        let sk =
            Secp256k1PrivateKey::from_wif("L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy")
                .unwrap();
        let typed_private_key = TypedPrivateKey::Secp256k1(sk);
        let coin_infos = vec![
            (
                coin_info_from_param("LITECOIN", "MAINNET", "NONE", "").unwrap(),
                "T7kFQq8eJeq6JhQjRZENW33NT1Pdhwpuw95SyJVeMXPckupR26ch",
            ),
            (
                coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap(),
                "cSGyRzqKLLYkhJF8GL6df1148P3jJJuiByKfDvKcHfsTVmFfuwaS",
            ),
            (
                coin_info_from_param("BITCOINCASH", "MAINNET", "NONE", "").unwrap(),
                "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy",
            ),
            (
                coin_info_from_param("BITCOINCASH", "TESTNET", "NONE", "").unwrap(),
                "cSGyRzqKLLYkhJF8GL6df1148P3jJJuiByKfDvKcHfsTVmFfuwaS",
            ),
        ];
        for (coin_info, wif) in coin_infos {
            assert_eq!(wif, typed_private_key.fmt(&coin_info).unwrap());
        }
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "28071bf4e2b0340db41b807ed8a5514139e5d6427ff9d58dbd22b7ed187103a4";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let mut coin_info = CoinInfo {
            coin: "BITCOINCASH".to_string(),
            derivation_path: "m/44'/2'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let address = BchAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "qruxj7zq6yzpdx8dld0e9hfvt7u47zrw9gfr5hy0vh");
    }
}
