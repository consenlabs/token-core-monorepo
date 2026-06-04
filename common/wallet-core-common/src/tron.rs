use bitcoin::base58;
use bitcoin::secp256k1::{Error, PublicKey};
use keccak_hash::keccak;

const TRON_ADDRESS_PREFIX: u8 = 0x41;
const TRON_ADDRESS_LENGTH: usize = 21;

pub fn address_from_pubkey(pub_key: &[u8]) -> Result<String, Error> {
    let public_key = PublicKey::from_slice(pub_key)?.serialize_uncompressed();
    let hash = keccak(&public_key[1..]);
    let payload = [vec![TRON_ADDRESS_PREFIX], hash[12..].to_vec()].concat();
    Ok(base58::encode_check(&payload))
}

pub fn is_valid_address(address: &str) -> bool {
    match base58::decode_check(address) {
        Ok(data) => data.len() == TRON_ADDRESS_LENGTH && data[0] == TRON_ADDRESS_PREFIX,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_address_from_uncompressed_pubkey() {
        let pubkey = hex::decode("04DAAC763B1B3492720E404C53D323BAF29391996F7DD5FA27EF0D12F7D50D694700684A32AD97FF4C09BF9CF0B9D0AC7F0091D9C6CB8BE9BB6A1106DA557285D8").unwrap();
        assert_eq!(
            address_from_pubkey(&pubkey).unwrap(),
            "THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq"
        );
    }

    #[test]
    fn validates_tron_base58check_addresses() {
        assert!(is_valid_address("THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acotq"));
        assert!(!is_valid_address("THfuSDVRvSsjNDPFdGjMU19Ha4Kf7acot"));
        assert!(!is_valid_address(
            "qq9j7zsvxxl7qsrtpnxp8q0ahcc3j3k6mss7mnlrj8"
        ));
        assert!(!is_valid_address("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN"));
    }
}
