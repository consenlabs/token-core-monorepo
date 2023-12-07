use crate::Result;

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let ret_data;
    if value.starts_with("0x") {
        ret_data = hex::decode(&value[2..value.len()])?
    } else {
        ret_data = hex::decode(value)?
    }

    Ok(ret_data)
}

pub fn utf8_or_hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    if value.starts_with("0x") {
        hex_to_bytes(value)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}
