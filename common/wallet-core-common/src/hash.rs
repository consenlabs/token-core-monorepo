use bitcoin::hashes::{ripemd160, sha256, sha256d, Hash};

pub type Hash256 = [u8; 32];
pub type Hash160 = [u8; 20];

pub fn merkle_hash(data: &[u8]) -> Hash256 {
    assert!(!data.is_empty(), "data should not be empty");

    let mut hashes = data.chunks(1024).map(sha256d).collect::<Vec<Hash256>>();
    let mut len = hashes.len();
    let mut data = [0u8; 64];

    while len > 1 {
        let mut i = 0;
        while i < len {
            data[..32].clone_from_slice(&hashes[i]);
            data[32..].clone_from_slice(&hashes[if i + 1 < len { i + 1 } else { i }]);

            hashes[i / 2] = sha256d(&data);
            i += 2;
        }

        len = (len + 1) / 2;
    }

    hashes[0]
}

#[inline]
pub fn sha256(data: &[u8]) -> Hash256 {
    sha256::Hash::hash(data).to_byte_array()
}

#[inline]
pub fn sha256d(data: &[u8]) -> Hash256 {
    sha256d::Hash::hash(data).to_byte_array()
}

#[inline]
pub fn keccak256(data: &[u8]) -> Hash256 {
    keccak_hash::keccak(data).to_fixed_bytes()
}

#[inline]
pub fn ripemd160(bytes: &[u8]) -> Hash160 {
    ripemd160::Hash::hash(bytes).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode;

    #[test]
    fn hashes_sha256_sha256d_keccak_and_ripemd160() {
        assert_eq!(
            encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode(sha256d(b"abc")),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );
        assert_eq!(
            encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            encode(ripemd160(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn merkle_hash_matches_existing_vector() {
        assert_eq!(
            encode(merkle_hash(&vec![0u8; 1024])),
            "5a6c9dcbec66882a3de754eb13e61d8908e6c0b67a23c9d524224ecd93746290"
        );
    }
}
