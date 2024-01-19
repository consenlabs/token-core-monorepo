use bitcoin::util::base58;
use core::str::FromStr;

use tcx_common::keccak256;

use tcx_constants::CoinInfo;
use tcx_keystore::Address;
use tcx_keystore::Result;
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct TronAddress(pub String);

impl Address for TronAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let pk = public_key.as_secp256k1()?;
        let bytes = pk.to_uncompressed();

        let hash = keccak256(&bytes[1..]);
        let hex: Vec<u8> = [vec![0x41], hash[12..32].to_vec()].concat();
        Ok(TronAddress(base58::check_encode_slice(&hex)))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let decode_ret = base58::from_check(address);
        if let Ok(data) = decode_ret {
            data.len() == 21 && data[0] == 0x41
        } else {
            false
        }
    }
}

impl FromStr for TronAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(TronAddress(s.to_string()))
    }
}

impl ToString for TronAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::Address;
    use crate::TronAddress;
    use tcx_common::FromHex;
    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{Keystore, Metadata};
    use tcx_primitive::{TypedPrivateKey, TypedPublicKey};

    #[test]
    fn tron_address() {
        let bytes = Vec::from_hex("04DAAC763B1B3492720E404C53D323BAF29391996F7DD5FA27EF0D12F7D50D694700684A32AD97FF4C09BF9CF0B9D0AC7F0091D9C6CB8BE9BB6A1106DA557285D8").unwrap();
        let coin_info = CoinInfo {
            coin: "".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        assert_eq!(
            TronAddress::from_public_key(
                &TypedPublicKey::from_slice(CurveType::SECP256k1, &bytes).unwrap(),
                &coin_info
            )
            .unwrap()
            .to_string(),
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq"
        );
    }

    #[test]
    fn tron_address_validation() {
        let coin_info = coin_info_from_param("TRON", "", "", "").unwrap();
        assert!(TronAddress::is_valid(
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq",
            &coin_info
        ));
        assert!(!TronAddress::is_valid(
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acot",
            &coin_info
        ));
        assert!(!TronAddress::is_valid(
            "qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8",
            &coin_info
        ));
        assert!(!TronAddress::is_valid(
            "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
            &coin_info
        ));
    }

    #[test]
    fn test_address_from_str() {
        let tezos_address = TronAddress::from_str("THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq").unwrap();
        assert_eq!(
            tezos_address.to_string(),
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq"
        );
    }

    #[test]
    fn test_derive_address() {
        let coin_info = coin_info_from_param("TRON", "", "", "").unwrap();
        let mut keystore =
            Keystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(&TEST_PASSWORD).unwrap();

        let acc = keystore.derive_coin::<TronAddress>(&coin_info).unwrap();
        assert_eq!(acc.address, "TY2uroBeZ5trA9QT96aEWj32XLkAAhQ9R2");
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "2d8f68944bdbfbc0769542fba8fc2d2a3de67393334471624364c7006da2aa54";
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
        let address = TronAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC");

        let prv_str = "BE88DF1D0BF30A923CB39C3BB953178BAAF3726E8D3CE81E7C8462E046E0D835";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let address = TronAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "THRF3GuPnvvPzKoaT8pJex5XHmo8NNbCb3");
    }
}
