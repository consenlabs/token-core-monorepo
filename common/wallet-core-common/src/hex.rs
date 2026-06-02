pub fn encode<T: AsRef<[u8]>>(value: T) -> String {
    ::hex::encode(value)
}

pub fn encode_0x<T: AsRef<[u8]>>(value: T) -> String {
    format!("0x{}", encode(value))
}

pub fn decode<T: AsRef<[u8]>>(value: T) -> Result<Vec<u8>, ::hex::FromHexError> {
    ::hex::decode(value)
}

pub fn decode_0x<T: AsRef<[u8]>>(value: T) -> Result<Vec<u8>, ::hex::FromHexError> {
    decode(strip_0x_compat(value.as_ref()))
}

pub fn decode_auto<T: AsRef<[u8]>>(value: T) -> Result<Vec<u8>, ::hex::FromHexError> {
    let bytes = value.as_ref();
    if has_0x_prefix(bytes) {
        decode_0x(value)
    } else {
        decode(value)
    }
}

pub trait ToHex {
    fn to_hex(&self) -> String;

    fn to_0x_hex(&self) -> String {
        format!("0x{}", self.to_hex())
    }
}

pub trait FromHex<Error = ::hex::FromHexError>
where
    Self: Sized,
{
    fn from_hex<T: AsRef<[u8]>>(value: T) -> Result<Self, Error>;

    fn from_0x_hex<T: AsRef<[u8]>>(value: T) -> Result<Self, Error> {
        if value.as_ref().is_empty() {
            return Self::from_hex("");
        }

        Self::from_hex(strip_0x_compat(value.as_ref()))
    }

    fn from_hex_auto<T: AsRef<[u8]>>(value: T) -> Result<Self, Error> {
        let bytes = value.as_ref();
        if has_0x_prefix(bytes) {
            Self::from_0x_hex(value)
        } else {
            Self::from_hex(value)
        }
    }
}

impl<T: AsRef<[u8]>> ToHex for T {
    fn to_hex(&self) -> String {
        encode(self)
    }
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        encode(self)
    }
}

impl FromHex for Vec<u8> {
    fn from_hex<T: AsRef<[u8]>>(value: T) -> Result<Self, ::hex::FromHexError> {
        decode(value)
    }
}

pub fn has_0x_prefix(value: &[u8]) -> bool {
    value.len() >= 2 && value[0] == b'0' && (value[1] == b'x' || value[1] == b'X')
}

pub fn strip_0x_compat(value: &[u8]) -> &[u8] {
    if value.is_empty() {
        value
    } else {
        &value[2..value.len()]
    }
}

pub fn utf8_or_hex_to_bytes(value: &str) -> Vec<u8> {
    if value.to_lowercase().starts_with("0x") {
        decode_0x(value).unwrap_or_else(|_| value.as_bytes().to_vec())
    } else {
        value.as_bytes().to_vec()
    }
}

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>, ::hex::FromHexError> {
    decode_auto(value)
}

pub fn is_valid_hex(input: &str) -> bool {
    let value = if has_0x_prefix(input.as_bytes()) {
        &input[2..]
    } else {
        input
    };

    !value.is_empty() && value.len() % 2 == 0 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_hex_with_and_without_prefix() {
        assert_eq!(encode([0x01, 0x02, 0x03, 0x04]), "01020304");
        assert_eq!(encode_0x([0x01, 0x02, 0x03, 0x04]), "0x01020304");
        assert_eq!(encode(Vec::<u8>::new()), "");
        assert_eq!(encode_0x(Vec::<u8>::new()), "0x");
    }

    #[test]
    fn decodes_hex_with_compat_prefix_rules() {
        assert_eq!(decode("01020304").unwrap(), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_0x("0x01020304").unwrap(), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_auto("0X01020304").unwrap(), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_auto("01020304").unwrap(), [0x01, 0x02, 0x03, 0x04]);
        assert!(decode_0x("0x010203041").is_err());
    }

    #[test]
    fn treats_0x_prefixed_valid_hex_as_bytes_and_other_input_as_utf8() {
        assert_eq!(utf8_or_hex_to_bytes("0x1234"), [0x12, 0x34]);
        assert_eq!(utf8_or_hex_to_bytes("1234"), b"1234");
        assert_eq!(utf8_or_hex_to_bytes("0x1234abcd"), [0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(utf8_or_hex_to_bytes("1234abcd"), b"1234abcd");
        assert_eq!(utf8_or_hex_to_bytes("0x1234abc"), b"0x1234abc");
    }

    #[test]
    fn exposes_legacy_hex_traits() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(data.to_hex(), "01020304");
        assert_eq!(data.to_0x_hex(), "0x01020304");
        assert_eq!(Vec::from_hex("01020304").unwrap(), data);
        assert_eq!(Vec::from_0x_hex("0x01020304").unwrap(), data);
        assert_eq!(Vec::from_hex_auto("0X01020304").unwrap(), data);
    }

    #[test]
    fn validates_hex_with_optional_0x_prefix() {
        assert!(is_valid_hex("666f6f626172"));
        assert!(is_valid_hex("0x666f6f626172"));
        assert!(!is_valid_hex(""));
        assert!(!is_valid_hex("0x"));
        assert!(!is_valid_hex("Hello imKey"));
        assert!(!is_valid_hex("123"));
    }
}
