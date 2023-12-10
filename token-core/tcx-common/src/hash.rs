use bitcoin::hashes::{ripemd160, sha256, sha256d, Hash};

pub type Hash256 = [u8; 32];
pub type Hash160 = [u8; 20];

pub fn merkle_hash(data: &[u8]) -> Hash256 {
    assert!(!data.is_empty(), "data should not be empty");

    let mut hashes = data
        .chunks(1024)
        .map(|chunk| sha256d(chunk))
        .collect::<Vec<Hash256>>();

    let mut len = hashes.len();
    let mut data = [0u8; 64];

    //loop until we have a single hash
    while len > 1 {
        //hash pairs of items
        let mut i = 0;
        while i < len {
            data[..32].clone_from_slice(&hashes[i]);
            data[32..].clone_from_slice(
                &hashes[{
                    if i + 1 < len {
                        i + 1
                    } else {
                        i
                    }
                }],
            );

            hashes[i / 2] = sha256d(&data);
            i += 2;
        }

        len = (len + 1) / 2;
    }

    hashes[0]
}

#[inline]
pub fn sha256(data: &[u8]) -> Hash256 {
    sha256::Hash::hash(data).into_inner()
}

#[inline]
pub fn sha256d(data: &[u8]) -> Hash256 {
    sha256d::Hash::hash(data).into_inner()
}

#[inline]
pub fn keccak256(data: &[u8]) -> Hash256 {
    keccak_hash::keccak(data).to_fixed_bytes()
}

#[inline]
pub fn ripemd160(bytes: &[u8]) -> Hash160 {
    ripemd160::Hash::hash(bytes).into_inner()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToHex;

    #[test]
    fn test_merkle_hash() {
        let tests = vec![
            (
                1000,
                "3fa2b684fa9d80f04b70187e6c9ff1c8dd422ce1846beb79cf5e1546c7062d41",
            ),
            (
                2000,
                "4b19aa611413ba9a6b89a2be7833bb835349b9e9e9872c5eacfc82daa2e5f08f",
            ),
            (
                3000,
                "c9ec2ec071ed70d02802decd912a1e8d124420556789384efaab80fcb7ce7ecb",
            ),
            (
                4000,
                "5cfa6745c50787e3d97a1322789713036f8cab7ba534d2a996bea015d811640c",
            ),
            (
                5000,
                "233bc40f24c071507474a9c978f0f0099d0c457f9874326640be55a8a8b96325",
            ),
            (
                1024,
                "5a6c9dcbec66882a3de754eb13e61d8908e6c0b67a23c9d524224ecd93746290",
            ),
            (
                2048,
                "5ee830087937da00520c4ce3793c5c7b951d37771d69a098415ddf7d682a39d9",
            ),
        ];

        for t in tests {
            let mut data = vec![0u8; t.0];

            for i in 0..t.0 {
                data[i] = (i / 1024 % 0xff) as u8;
            }

            assert_eq!(merkle_hash(&data).to_hex(), t.1);
        }
    }
}
