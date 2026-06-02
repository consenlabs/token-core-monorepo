use blake2b_rs::Blake2bBuilder;

pub enum HashSize {
    Default = 32,
}

pub fn digest(ingest: &[u8], hash_size: HashSize) -> Vec<u8> {
    //allocate max length byte
    let mut result = [0u8; 32];

    let size = hash_size as usize;
    let mut hasher = Blake2bBuilder::new(size).build();
    hasher.update(ingest);
    hasher.finalize(&mut result);
    result[0..size].to_vec()
}

#[cfg(test)]
mod tests {
    use crate::utils::{digest, HashSize};

    #[test]
    fn test_digest() {
        let payload = [1u8, 2];

        assert_eq!(
            digest(&payload, HashSize::Default),
            vec![
                101, 218, 57, 134, 234, 236, 240, 70, 203, 44, 65, 103, 58, 237, 157, 78, 30, 102,
                23, 48, 220, 49, 198, 47, 50, 125, 245, 209, 89, 51, 89, 93,
            ]
        );
    }
}
