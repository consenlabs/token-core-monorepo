//! Pure CKB helpers shared by TokenCoreX and imKeyCore.

pub mod molecule {
    const U32_SIZE: u32 = 4;

    fn calculate_offsets(element_lengths: &[u32]) -> (u32, Vec<u32>) {
        let header_length = U32_SIZE + U32_SIZE * element_lengths.len() as u32;
        let mut offsets = Vec::with_capacity(element_lengths.len());
        let mut total = header_length;

        for element_length in element_lengths {
            offsets.push(total);
            total += element_length;
        }

        (total, offsets)
    }

    pub fn serialize_u32(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    pub fn serialize_u64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    pub fn serialize_struct(values: &[&[u8]]) -> Vec<u8> {
        let total_size = values.iter().map(|item| item.len()).sum();
        let mut ret = Vec::with_capacity(total_size);

        for item in values {
            ret.extend_from_slice(item);
        }

        ret
    }

    /// Serialize a Molecule dynamic vector.
    pub fn serialize_dynamic_vec(values: &[&[u8]]) -> Vec<u8> {
        let element_lengths: Vec<u32> = values.iter().map(|item| item.len() as u32).collect();
        let body_size = element_lengths.iter().sum::<u32>() as usize;
        let mut body = Vec::with_capacity(body_size);

        for item in values {
            body.extend_from_slice(item);
        }

        let (full_size, offsets) = calculate_offsets(&element_lengths);
        let mut ret = Vec::with_capacity(full_size as usize);
        ret.extend(serialize_u32(full_size));

        for offset in offsets {
            ret.extend(serialize_u32(offset));
        }

        ret.extend(body);
        ret
    }

    pub fn serialize_fixed_vec(values: &[&[u8]]) -> Vec<u8> {
        let body_size = values.iter().map(|item| item.len()).sum::<usize>();
        let mut ret = Vec::with_capacity(U32_SIZE as usize + body_size);
        ret.extend(serialize_u32(body_size as u32));

        for item in values {
            ret.extend_from_slice(item);
        }

        ret
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serialize_integer_values_as_little_endian() {
            assert_eq!(hex::encode(serialize_u32(0x12345678)), "78563412");
            assert_eq!(
                hex::encode(serialize_u64(0x0123456789abcdef)),
                "efcdab8967452301"
            );
        }

        #[test]
        fn serialize_struct_concatenates_values() {
            let bytes = serialize_struct(&[
                vec![0x11u8, 0x13u8].as_slice(),
                vec![0x20u8, 0x17u8, 0x9u8].as_slice(),
            ]);
            assert_eq!(hex::encode(bytes), "1113201709");
        }

        #[test]
        fn serialize_fixed_vec_prefixes_body_size() {
            let item = hex::decode("1234567890abcdef").unwrap();
            let bytes = serialize_fixed_vec(&[item.as_slice()]);
            assert_eq!(hex::encode(bytes), "080000001234567890abcdef");
        }

        #[test]
        fn serialize_dynamic_vec_matches_golden_vectors() {
            let bytes = serialize_dynamic_vec(&[]);
            assert_eq!(hex::encode(bytes), "04000000");

            let item = hex::decode("020000001234").unwrap();
            let bytes = serialize_dynamic_vec(&[item.as_slice()]);
            assert_eq!(hex::encode(bytes), "0e00000008000000020000001234");

            let item_1 = hex::decode("020000001234").unwrap();
            let item_2 = hex::decode("00000000").unwrap();
            let item_3 = hex::decode("020000000567").unwrap();
            let item_4 = hex::decode("0100000089").unwrap();
            let item_5 = hex::decode("03000000abcdef").unwrap();
            let bytes = serialize_dynamic_vec(&[
                item_1.as_slice(),
                item_2.as_slice(),
                item_3.as_slice(),
                item_4.as_slice(),
                item_5.as_slice(),
            ]);
            assert_eq!(hex::encode(bytes), "34000000180000001e00000022000000280000002d00000002000000123400000000020000000567010000008903000000abcdef");
        }
    }
}

#[cfg(feature = "ckb-address")]
pub mod address {
    use bech32::{Bech32, Hrp};
    use bitcoin::secp256k1::PublicKey;
    #[cfg(not(target_arch = "wasm32"))]
    use blake2b_rs::{Blake2b, Blake2bBuilder};
    #[cfg(target_arch = "wasm32")]
    use blake2b_simd::Params;
    use std::error::Error;
    use std::fmt;

    const TYPE_FULL_DATA: u8 = 2;
    const TYPE_FULL_TYPE: u8 = 4;
    const TYPE_SHORT: u8 = 1;
    const SHORT_ADDRESS_CODE_HASH_INDEX: u8 = 0;
    const SHORT_ADDRESS_LENGTH: usize = 22;
    const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
    const BLANK_HASH: [u8; 32] = [
        68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231,
        239, 67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62,
    ];

    #[cfg(target_arch = "wasm32")]
    struct Blake2b {
        state: blake2b_simd::State,
    }

    #[cfg(target_arch = "wasm32")]
    impl Blake2b {
        fn update(&mut self, input: &[u8]) {
            self.state.update(input);
        }

        fn finalize(&self, output: &mut [u8]) {
            let hash = self.state.finalize();
            output.copy_from_slice(&hash.as_bytes()[..output.len()]);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddressError(String);

    impl AddressError {
        fn new(message: impl Into<String>) -> Self {
            Self(message.into())
        }
    }

    impl fmt::Display for AddressError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl Error for AddressError {}

    pub fn short_address_from_pubkey(network: &str, pubkey: &[u8]) -> Result<String, AddressError> {
        let prefix = hrp_for_network(network);
        let compressed_pubkey = PublicKey::from_slice(pubkey)
            .map_err(|err| AddressError::new(err.to_string()))?
            .serialize();
        let pubkey_hash = blake2b_160(compressed_pubkey);
        let mut payload = vec![TYPE_SHORT, SHORT_ADDRESS_CODE_HASH_INDEX];
        payload.extend(pubkey_hash);

        let hrp = Hrp::parse(prefix).map_err(|err| AddressError::new(err.to_string()))?;
        bech32::encode::<Bech32>(hrp, &payload).map_err(|err| AddressError::new(err.to_string()))
    }

    pub fn is_valid_address(address: &str, network: &str) -> bool {
        let Ok((hrp, data)) = bech32::decode(address) else {
            return false;
        };

        let Some(address_type) = data.first() else {
            return false;
        };

        if ![TYPE_FULL_DATA, TYPE_FULL_TYPE, TYPE_SHORT].contains(address_type) {
            return false;
        }

        if *address_type == TYPE_SHORT {
            if data.len() != SHORT_ADDRESS_LENGTH {
                return false;
            }

            let code_hash_index = data[1];
            if code_hash_index != 0 && code_hash_index != 1 {
                return false;
            }
        }

        match hrp.as_str() {
            "ckb" => network == "MAINNET",
            "ckt" => network == "TESTNET",
            _ => false,
        }
    }

    fn hrp_for_network(network: &str) -> &'static str {
        match network {
            "TESTNET" => "ckt",
            _ => "ckb",
        }
    }

    fn blake2b_160<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
        if data.as_ref().is_empty() {
            return BLANK_HASH[..20].to_vec();
        }

        let mut result = [0_u8; 32];
        let mut blake2b = new_blake2b();
        blake2b.update(data.as_ref());
        blake2b.finalize(&mut result);
        result[..20].to_vec()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn new_blake2b() -> Blake2b {
        Blake2bBuilder::new(32)
            .personal(CKB_HASH_PERSONALIZATION)
            .build()
    }

    #[cfg(target_arch = "wasm32")]
    fn new_blake2b() -> Blake2b {
        Blake2b {
            state: Params::new()
                .hash_length(32)
                .personal(CKB_HASH_PERSONALIZATION)
                .to_state(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn derives_short_address_from_public_key() {
            let pubkey =
                hex::decode("024a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01")
                    .unwrap();

            assert_eq!(
                short_address_from_pubkey("TESTNET", &pubkey).unwrap(),
                "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83"
            );
            assert_eq!(
                short_address_from_pubkey("MAINNET", &pubkey).unwrap(),
                "ckb1qyqrdsefa43s6m882pcj53m4gdnj4k440axqdt9rtd"
            );
        }

        #[test]
        fn validates_short_address_network_and_payload() {
            assert!(is_valid_address(
                "ckt1qyqd5eyygtdmwdr7ge736zw6z0ju6wsw7rssu8fcve",
                "TESTNET"
            ));
            assert!(is_valid_address(
                "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq",
                "MAINNET"
            ));
            assert!(!is_valid_address(
                "ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryg",
                "MAINNET"
            ));
            assert!(!is_valid_address(
                "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqqm65l9j",
                "TESTNET"
            ));
            assert!(!is_valid_address(
                "test1qyqrdsefa43s6m882pcj53m4gdnj4k440axqpkzhhy",
                "TESTNET"
            ));
        }
    }
}
