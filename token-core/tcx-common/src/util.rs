use crate::FromHex;
use crate::Result;

pub fn utf8_or_hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    if value.to_lowercase().starts_with("0x") {
        FromHex::from_hex_auto(value)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}
