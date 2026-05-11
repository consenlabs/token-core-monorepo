use blake2b_simd::{Params, State};

pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub const BLANK_HASH: [u8; 32] = [
    68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231, 239,
    67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62,
];

/// Streaming Blake2b-256 hasher with the CKB personalization. Wraps
/// `blake2b_simd::State` so callers can keep the existing
/// `update`/`finalize(&mut [u8])` ergonomics that previously came from
/// `blake2b-rs` (which is not WASM-compatible because of its C bindings).
pub struct CkbBlake2b {
    state: State,
}

impl CkbBlake2b {
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.state.update(data);
        self
    }

    pub fn finalize(&mut self, dst: &mut [u8]) {
        let hash = self.state.finalize();
        let bytes = hash.as_bytes();
        let len = dst.len().min(bytes.len());
        dst[..len].copy_from_slice(&bytes[..len]);
    }
}

pub fn new_blake2b() -> CkbBlake2b {
    let state = Params::new()
        .hash_length(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .to_state();
    CkbBlake2b { state }
}

pub fn blake2b_256<T: AsRef<[u8]>>(s: T) -> Vec<u8> {
    if s.as_ref().is_empty() {
        return BLANK_HASH.to_vec();
    }

    inner_blake2b_256(s).to_vec()
}

pub fn blake2b_160<T: AsRef<[u8]>>(s: T) -> Vec<u8> {
    if s.as_ref().is_empty() {
        return BLANK_HASH[..20].to_vec();
    }

    inner_blake2b_256(s)[..20].to_vec()
}

fn inner_blake2b_256<T: AsRef<[u8]>>(s: T) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut blake2b = new_blake2b();
    blake2b.update(s.as_ref());
    blake2b.finalize(&mut result);
    result
}

#[cfg(test)]
mod test {
    use crate::hash::{blake2b_160, blake2b_256};
    #[test]
    fn test_blake2b_256_param_is_empty() {
        let hash = blake2b_256(vec![]);
        assert_eq!(
            hash,
            [
                68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155,
                196, 231, 239, 67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62
            ]
        );
    }

    #[test]
    fn test_blake2b_160_param_is_empty() {
        let hash = blake2b_160(vec![]);
        assert_eq!(
            hash,
            [
                68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155,
                196, 231, 239
            ]
        );
    }
}
