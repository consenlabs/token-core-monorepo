use bitcoin::util::base58;
use blake2b_simd::Params;
use std::str::FromStr;
use tcx_common::{sha256, sha256d};
use tcx_constants::CoinInfo;
use tcx_keystore::Address;
use tcx_keystore::PublicKeyEncoder;
use tcx_keystore::Result;
use tcx_primitive::TypedPublicKey;

use tcx_common::FromHex;

#[derive(PartialEq, Eq, Clone)]
pub struct TezosPublicKeyEncoder {}

impl PublicKeyEncoder for TezosPublicKeyEncoder {
    fn encode(public_key: &TypedPublicKey, coin_info: &CoinInfo) -> Result<String> {
        let edpk_prefix: Vec<u8> = vec![0x0D, 0x0F, 0x25, 0xD9];
        let to_hash = [edpk_prefix, public_key.to_bytes()].concat();
        let hashed = sha256d(&to_hash);
        let hash_with_checksum = [to_hash, hashed[0..4].to_vec()].concat();
        let edpk = base58::encode_slice(&hash_with_checksum);
        Ok(edpk)
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct TezosAddress(String);

impl Address for TezosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let tz1_prefix = Vec::from_hex("06A19F")?;
        //get public key
        let pubkey = public_key.to_bytes();
        //Perform Blake2B hashing on the public key（no prefix）
        let mut params = Params::new();
        params.hash_length(20);
        let generic_hash = params.hash(&pubkey[..32]);
        //sha256Twice(prefix<3> + public key hash<20>)
        let mut prefixed_generic_hash = vec![];
        prefixed_generic_hash.extend_from_slice(tz1_prefix.as_ref());
        prefixed_generic_hash.extend_from_slice(generic_hash.as_bytes());
        let double_hash_result = sha256(&sha256(&prefixed_generic_hash));
        prefixed_generic_hash.extend_from_slice(&double_hash_result[..4]);
        //base58Encode(prefix<3> + public key hash<20> + checksum<4>)
        let address = base58::encode_slice(prefixed_generic_hash.as_slice());

        Ok(TezosAddress(address))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let decode_result = base58::from(address);
        if decode_result.is_err() {
            return false;
        };

        let decode_data = decode_result.unwrap();
        let hash_res = sha256(&sha256(&decode_data[..decode_data.len() - 4]));
        for number in 0..4 {
            if hash_res[number] != decode_data[decode_data.len() - 4 + number] {
                return false;
            }
        }
        true
    }
}

impl ToString for TezosAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl FromStr for TezosAddress {
    type Err = failure::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(TezosAddress(s.to_string()))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::address::TezosAddress;
    use hex::FromHex;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::Address;
    use tcx_primitive::TypedPublicKey;

    #[test]
    fn from_public_key_test() {
        let coin_info = CoinInfo {
            coin: "TEZOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
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

        let _pub_key = TypedPublicKey::from_slice(
            CurveType::ED25519,
            &Vec::from_hex("d0c5ee97112a8a6f192ec44ab10f6a51bbfa327f7736e8e8b30b9ec636bc533b")
                .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn is_valid_test() {
        let coin_info = CoinInfo {
            coin: "TEZOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
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
    fn test_address_from_str() {
        let tezos_address = TezosAddress::from_str("tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9").unwrap();
        assert_eq!(
            tezos_address.to_string(),
            "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9"
        );
    }
}
