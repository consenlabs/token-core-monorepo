use base32::Alphabet;
use blake2b_rs::Blake2bBuilder;

const CHECKSUM_HASH_SIZE: usize = 4;
const PAYLOAD_HASH_SIZE: usize = 20;
const SECP256K1_PROTOCOL: u8 = 1;
const BLS_PROTOCOL: u8 = 3;

pub fn secp256k1_address_from_uncompressed_pubkey(network_prefix: &str, pub_key: &[u8]) -> String {
    address_from_payload(
        network_prefix,
        SECP256K1_PROTOCOL,
        &digest(pub_key, PAYLOAD_HASH_SIZE),
    )
}

pub fn bls_address_from_public_key(network_prefix: &str, pub_key: &[u8]) -> String {
    address_from_payload(network_prefix, BLS_PROTOCOL, pub_key)
}

fn address_from_payload(network_prefix: &str, protocol: u8, payload: &[u8]) -> String {
    let checksum = digest(
        &[vec![protocol], payload.to_vec()].concat(),
        CHECKSUM_HASH_SIZE,
    );
    format!(
        "{}{}{}",
        network_prefix,
        protocol,
        base32::encode(
            Alphabet::Rfc4648 { padding: false },
            &[payload, checksum.as_slice()].concat(),
        )
        .to_lowercase()
    )
}

fn digest(ingest: &[u8], hash_size: usize) -> Vec<u8> {
    let mut hash = vec![0; hash_size];
    let mut blake2b = Blake2bBuilder::new(hash_size).build();
    blake2b.update(ingest);
    blake2b.finalize(hash.as_mut_slice());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_secp256k1_address_from_uncompressed_public_key() {
        let pubkey = vec![
            4, 148, 2, 250, 195, 126, 100, 50, 164, 22, 163, 160, 202, 84, 38, 181, 24, 90, 179,
            178, 79, 97, 52, 239, 162, 92, 228, 135, 200, 45, 46, 78, 19, 191, 69, 37, 17, 224,
            210, 36, 84, 33, 248, 97, 59, 193, 13, 114, 250, 33, 102, 102, 169, 108, 59, 193, 57,
            32, 211, 255, 35, 63, 208, 188, 5,
        ];

        assert_eq!(
            secp256k1_address_from_uncompressed_pubkey("t", &pubkey),
            "t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq"
        );
    }

    #[test]
    fn derives_bls_address_from_public_key() {
        let pubkey = vec![
            173, 88, 223, 105, 110, 45, 78, 145, 234, 134, 200, 129, 233, 56, 186, 78, 168, 27, 57,
            94, 18, 121, 123, 132, 185, 207, 49, 75, 149, 70, 112, 94, 131, 156, 122, 153, 214, 6,
            178, 71, 221, 180, 249, 172, 122, 52, 20, 221,
        ];

        assert_eq!(
            bls_address_from_public_key("t", &pubkey),
            "t3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a"
        );
    }
}
