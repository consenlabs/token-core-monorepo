use bitcoin::base58;
use bitcoin::hashes::{sha256, Hash};
use blake2b_simd::Params;

const EDPK_PREFIX: [u8; 4] = [0x0D, 0x0F, 0x25, 0xD9];
const TZ1_PREFIX: [u8; 3] = [0x06, 0xA1, 0x9F];

pub fn encode_ed25519_public_key(pub_key: &[u8]) -> String {
    let payload = with_checksum(&[EDPK_PREFIX.as_slice(), pub_key].concat());
    base58::encode(&payload)
}

pub fn tz1_address_from_public_key(pub_key: &[u8]) -> Option<String> {
    if pub_key.len() < 32 {
        return None;
    }

    let mut params = Params::new();
    params.hash_length(20);
    let generic_hash = params.hash(&pub_key[..32]);
    let payload = [TZ1_PREFIX.as_slice(), generic_hash.as_bytes()].concat();
    Some(base58::encode(with_checksum(&payload).as_slice()))
}

pub fn is_valid_base58check(value: &str) -> bool {
    let Ok(decoded) = base58::decode(value) else {
        return false;
    };

    if decoded.len() < 4 {
        return false;
    }

    let checksum_start = decoded.len() - 4;
    let expected_checksum = sha256d(&decoded[..checksum_start]);
    decoded[checksum_start..] == expected_checksum[..4]
}

fn with_checksum(payload: &[u8]) -> Vec<u8> {
    let checksum = sha256d(payload);
    [payload, &checksum[..4]].concat()
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(sha256::Hash::hash(data).as_byte_array()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_tz1_address_from_public_key() {
        let pubkey =
            hex::decode("4a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                .unwrap();
        assert_eq!(
            tz1_address_from_public_key(&pubkey).unwrap(),
            "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9"
        );

        let pubkey =
            hex::decode("d0c5ee97112a8a6f192ec44ab10f6a51bbfa327f7736e8e8b30b9ec636bc533b")
                .unwrap();
        assert_eq!(
            tz1_address_from_public_key(&pubkey).unwrap(),
            "tz1KenEed7WbMRsNUBv24vnCzVgbdrvy44cr"
        );
    }

    #[test]
    fn encodes_ed25519_public_key() {
        let pubkey =
            hex::decode("4a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                .unwrap();
        assert_eq!(
            encode_ed25519_public_key(&pubkey),
            "edpkuCxAMMrmdQZwVafQPJZZqcEj9FizeoXYovmLQyokYJcG7CYD8o"
        );
    }

    #[test]
    fn validates_base58check_checksum() {
        assert!(is_valid_base58check("tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNo9"));
        assert!(!is_valid_base58check(
            "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S7xNoI"
        ));
        assert!(!is_valid_base58check(
            "tz1dLEU3WfzCrDq2bvoEz4cfLP5wg4S3DxBZ"
        ));
    }
}
