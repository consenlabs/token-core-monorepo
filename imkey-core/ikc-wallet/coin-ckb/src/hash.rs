#[cfg(not(target_arch = "wasm32"))]
use blake2b_rs::{Blake2b, Blake2bBuilder};
#[cfg(target_arch = "wasm32")]
use blake2b_simd::Params;

pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub const BLANK_HASH: [u8; 32] = [
    68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231, 239,
    67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62,
];

#[cfg(target_arch = "wasm32")]
pub struct Blake2b {
    state: blake2b_simd::State,
}

#[cfg(target_arch = "wasm32")]
impl Blake2b {
    pub fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub fn finalize(&self, output: &mut [u8]) {
        let hash = self.state.finalize();
        output.copy_from_slice(&hash.as_bytes()[..output.len()]);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

#[cfg(target_arch = "wasm32")]
pub fn new_blake2b() -> Blake2b {
    Blake2b {
        state: Params::new()
            .hash_length(32)
            .personal(CKB_HASH_PERSONALIZATION)
            .to_state(),
    }
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
