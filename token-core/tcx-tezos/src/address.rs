use std::str::FromStr;
use tcx_constants::CoinInfo;
use tcx_keystore::Address;
use tcx_keystore::PublicKeyEncoder;
use tcx_keystore::Result;
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct TezosPublicKeyEncoder {}

impl PublicKeyEncoder for TezosPublicKeyEncoder {
    fn encode(public_key: &TypedPublicKey, _coin_info: &CoinInfo) -> Result<String> {
        Ok(wallet_core_common::tezos::encode_ed25519_public_key(
            &public_key.to_bytes(),
        ))
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct TezosAddress(String);

impl Address for TezosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        Ok(TezosAddress(
            wallet_core_common::tezos::tz1_address_from_public_key(&public_key.to_bytes())
                .ok_or_else(|| anyhow::anyhow!("invalid_public_key"))?,
        ))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        wallet_core_common::tezos::is_valid_base58check(address)
    }
}

impl ToString for TezosAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl FromStr for TezosAddress {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(TezosAddress(s.to_string()))
    }
}

#[cfg(test)]
mod test {

    use crate::address::TezosAddress;
    use hex::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::Address;
    use tcx_primitive::TypedPublicKey;

    #[test]
    fn from_public_key_test() {
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "TEZOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };

        let pub_key = TypedPublicKey::from_slice(
            CurveType::ED25519,
            &Vec::from_hex("4a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            TezosAddress::from_public_key(&pub_key, &coin_info)
                .unwrap()
                .to_string(),
            "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9"
        );

        let pub_key = TypedPublicKey::from_slice(
            CurveType::ED25519,
            &Vec::from_hex("d0c5ee97112a8a6f192ec44ab10f6a51bbfa327f7736e8e8b30b9ec636bc533b")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            TezosAddress::from_public_key(&pub_key, &coin_info)
                .unwrap()
                .to_string(),
            "tz1KenEed7WbMRsNUBv24vnCzVgbdrvy44cr"
        );
    }

    #[test]
    fn is_valid_test() {
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "TEZOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };
        let address = "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9"; //valid address
        let valid_result = TezosAddress::is_valid(address, &coin_info);
        assert!(valid_result);

        let address = "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNoI"; //base58 error address
        let valid_result = TezosAddress::is_valid(address, &coin_info);
        assert!(!valid_result);

        let address = "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S3DxBZ"; //checksum error address
        let valid_result = TezosAddress::is_valid(address, &coin_info);
        assert!(!valid_result);
    }

    #[test]
    fn cross_test_tw() {
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "TEZOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            contract_code: "".to_string(),
        };

        let pub_key = TypedPublicKey::from_slice(
            CurveType::ED25519,
            &Vec::from_hex("fe157cc8011727936c592f856c9071d39cf4acdadfa6d76435e4619c9dc56f63")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            TezosAddress::from_public_key(&pub_key, &coin_info)
                .unwrap()
                .to_string(),
            "tz1cG2jx3W4bZFeVGBjsTxUAG8tdpTXtE8PT"
        );
    }
}
