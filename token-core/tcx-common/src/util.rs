use crate::FromHex;
use crate::Result;

pub fn utf8_or_hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    if value.to_lowercase().starts_with("0x") {
        FromHex::from_0x_hex(value)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_utf8_or_hex_to_bytes() {
        let tests = vec![
            ("0x1234", vec![0x12, 0x34]),
            ("1234", vec![0x31, 0x32, 0x33, 0x34]),
            ("0x1234abcd", vec![0x12, 0x34, 0xab, 0xcd]),
            (
                "1234abcd",
                vec![0x31, 0x32, 0x33, 0x34, 0x61, 0x62, 0x63, 0x64],
            ),
        ];

        for t in tests {
            assert_eq!(super::utf8_or_hex_to_bytes(t.0).unwrap(), t.1);
        }
    }
}
