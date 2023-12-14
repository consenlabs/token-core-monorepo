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
    fn test_ripemd160() {
        let tests = vec![
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "b0e20b6e3116640286ed3a87a5713079b21f5189",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            ),
        ];

        for t in tests {
            assert_eq!(ripemd160(t.0.as_bytes()).to_hex(), t.1);
        }
    }

    #[test]
    fn test_sha256d() {
        //generate sha256d unit tests
        let tests = vec![
            (
                "",
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
            ),
            (
                "abc",
                "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "0cffe17f68954dac3a84fb1458bd5ec99209449749b2b308b7cb55812f9563af",
            ),
        ];

        for t in tests {
            assert_eq!(sha256d(t.0.as_bytes()).to_hex(), t.1);
        }
    }

    #[test]
    fn test_keccak256() {
        //generate keccak256 unit tests
        let tests = vec![
            (
                "abc",
                "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371",
            ),
        ];

        for t in tests {
            assert_eq!(keccak256(t.0.as_bytes()).to_hex(), t.1);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = vec![
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ];

        for t in tests {
            assert_eq!(sha256(t.0.as_bytes()).to_hex(), t.1);
        }
    }

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
