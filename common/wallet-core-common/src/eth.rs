use keccak_hash::keccak;

fn strip_0x(address: &str) -> &str {
    address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address)
}

fn is_hex_address_body(address: &str) -> bool {
    address.len() == 40 && address.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

pub fn checksum_address_bytes(address: &[u8], chain_id: Option<u8>) -> Option<String> {
    if address.len() != 20 {
        return None;
    }

    let address_hex = hex::encode(address);
    let hash_source = match chain_id {
        Some(chain_id) => format!("{chain_id}0x{address_hex}"),
        None => address_hex.clone(),
    };
    Some(apply_eip55_checksum(&address_hex, hash_source.as_bytes()))
}

pub fn checksum_hex_unchecked(address: &str) -> String {
    let address = strip_0x(address).to_ascii_lowercase();
    apply_eip55_checksum(&address, address.as_bytes())
}

pub fn address_bytes_from_uncompressed_pubkey(pub_key: &[u8]) -> Option<[u8; 20]> {
    if pub_key.len() < 65 {
        return None;
    }

    let pub_key_hash = keccak(&pub_key[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&pub_key_hash[12..]);
    Some(address)
}

pub fn checksum_address_from_uncompressed_pubkey(pub_key: &[u8]) -> Option<String> {
    let address = address_bytes_from_uncompressed_pubkey(pub_key)?;
    checksum_address_bytes(&address, None)
}

pub fn is_valid_address(address: &str) -> bool {
    if address.len() != 42 || !address.starts_with("0x") {
        return false;
    }

    let address_body = &address[2..];
    if !is_hex_address_body(address_body) {
        return false;
    }

    if address == address.to_ascii_lowercase() {
        return true;
    }

    checksum_hex_unchecked(address) == address
}

fn apply_eip55_checksum(address_hex: &str, hash_source: &[u8]) -> String {
    let hash = hex::encode(keccak(hash_source));
    let mut checksum_address = String::with_capacity(address_hex.len() + 2);
    checksum_address.push_str("0x");

    for (address_char, hash_char) in address_hex.chars().zip(hash.chars()) {
        let hash_nibble = hash_char.to_digit(16).expect("keccak hash is hex");
        if hash_nibble > 7 {
            checksum_address.push(address_char.to_ascii_uppercase());
        } else {
            checksum_address.push(address_char.to_ascii_lowercase());
        }
    }

    checksum_address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_checksum_address_from_uncompressed_pubkey() {
        let pubkey = hex::decode("04efb99d9860f4dec4cb548a5722c27e9ef58e37fbab9719c5b33d55c216db49311221a01f638ce5f255875b194e0acaa58b19a89d2e56a864427298f826a7f887").unwrap();
        assert_eq!(
            checksum_address_from_uncompressed_pubkey(&pubkey).unwrap(),
            "0xC2D7CF95645D33006175B78989035C7c9061d3F9"
        );
    }

    #[test]
    fn checksums_hex_address_with_optional_prefix() {
        assert_eq!(
            checksum_hex_unchecked("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            checksum_hex_unchecked("fb6916095ca1df60bb79ce92ce3ea74c37c5d359"),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
    }

    #[test]
    fn validates_legacy_lowercase_and_eip55_addresses() {
        assert!(is_valid_address(
            "0xef678007d18427e6022059dbc264f27507cd1ffc"
        ));
        assert!(is_valid_address(
            "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5"
        ));
        assert!(!is_valid_address(
            "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfE5"
        ));
        assert!(!is_valid_address(
            "0xef678007D18427E6022059Dbc264f27507CD1ffc"
        ));
        assert!(!is_valid_address(
            "ef678007D18427E6022059Dbc264f27507CD1ffC"
        ));
    }
}
