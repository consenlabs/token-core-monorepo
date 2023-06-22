use regex::Regex;

use crate::Result;

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>> {
    let ret_data;
    if value.to_lowercase().starts_with("0x") {
        ret_data = hex::decode(&value[2..value.len()])?
    } else {
        ret_data = hex::decode(value)?
    }
    Ok(ret_data)
}

pub fn string_to_bytes(value: &str) -> Result<Vec<u8>> {
    let ret_data;
    if is_valid_hex(value)? {
        if value.to_lowercase().starts_with("0x") {
            ret_data = hex::decode(&value[2..value.len()])?
        } else {
            ret_data = hex::decode(value)?
        }
    } else {
        ret_data = value.as_bytes().to_vec()
    }
    Ok(ret_data)
}

pub fn is_valid_hex(value: &str) -> Result<bool> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Ok(false);
    }

    let hex_regex = Regex::new(r"^(0x)?[0-9a-fA-F]+$").unwrap();
    if !hex_regex.is_match(value) {
        return Ok(false);
    }
    Ok(true)
}
