pub struct Serializer();

impl Serializer {
    pub fn serialize_u32(value: u32) -> Vec<u8> {
        wallet_core_common::ckb::molecule::serialize_u32(value)
    }

    pub fn serialize_u64(value: u64) -> Vec<u8> {
        wallet_core_common::ckb::molecule::serialize_u64(value)
    }

    pub fn serialize_struct(values: &[&[u8]]) -> Vec<u8> {
        wallet_core_common::ckb::molecule::serialize_struct(values)
    }

    pub fn serialize_dynamic_vec(values: &[&[u8]]) -> Vec<u8> {
        wallet_core_common::ckb::molecule::serialize_dynamic_vec(values)
    }

    pub fn serialize_fixed_vec(values: &[&[u8]]) -> Vec<u8> {
        wallet_core_common::ckb::molecule::serialize_fixed_vec(values)
    }
}

#[cfg(test)]
mod tests {
    use crate::serializer::Serializer;
    use tcx_common::{FromHex, ToHex};

    #[test]
    fn serialize_struct() {
        let bytes = Serializer::serialize_struct(&[
            vec![0x11u8, 0x13u8].as_slice(),
            vec![0x20u8, 0x17u8, 0x9u8].as_slice(),
        ]);
        assert_eq!(bytes.to_hex(), "1113201709");
    }

    #[test]
    fn serialize_fixed_vec() {
        let bytes = Serializer::serialize_fixed_vec(&[Vec::from_hex("1234567890abcdef")
            .unwrap()
            .as_slice()]);
        assert_eq!(bytes.to_hex(), "080000001234567890abcdef");
    }

    #[test]
    fn serialize_dynamic_vec() {
        let bytes = Serializer::serialize_dynamic_vec(&[]);
        assert_eq!(bytes.to_hex(), "04000000");

        let bytes =
            Serializer::serialize_dynamic_vec(&[Vec::from_hex("020000001234").unwrap().as_slice()]);
        assert_eq!(bytes.to_hex(), "0e00000008000000020000001234");

        let bytes = Serializer::serialize_dynamic_vec(&[
            Vec::from_hex("020000001234").unwrap().as_slice(),
            Vec::from_hex("00000000").unwrap().as_slice(),
            Vec::from_hex("020000000567").unwrap().as_slice(),
            Vec::from_hex("0100000089").unwrap().as_slice(),
            Vec::from_hex("03000000abcdef").unwrap().as_slice(),
        ]);
        assert_eq!(bytes.to_hex(), "34000000180000001e00000022000000280000002d00000002000000123400000000020000000567010000008903000000abcdef");
    }
}
