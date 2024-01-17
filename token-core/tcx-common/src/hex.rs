use super::Result;
use failure::format_err;

pub trait ToHex {
    fn to_hex(&self) -> String;

    fn to_0x_hex(&self) -> String {
        format!("0x{}", self.to_hex())
    }
}

pub trait FromHex
where
    Self: Sized,
{
    fn from_hex<T: AsRef<[u8]>>(value: T) -> Result<Self>;

    fn from_0x_hex<T: AsRef<[u8]>>(value: T) -> Result<Self> {
        if value.as_ref().len() == 0 {
            return Ok(Self::from_hex("")?);
        }

        let bytes = value.as_ref();
        Self::from_hex(&bytes[2..bytes.len()])
    }

    fn from_hex_auto<T: AsRef<[u8]>>(value: T) -> Result<Self> {
        let bytes = value.as_ref();
        if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
            Self::from_0x_hex(value)
        } else {
            Self::from_hex(value)
        }
    }
}

impl<T: AsRef<[u8]>> ToHex for T {
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
}

impl FromHex for Vec<u8> {
    fn from_hex<T: AsRef<[u8]>>(value: T) -> Result<Self> {
        hex::decode(value).map_err(|e| format_err!("{}", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{FromHex, ToHex};
    #[test]
    fn test_to_hex() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(data.to_hex(), "01020304");
    }

    #[test]
    fn test_to_hex_empty() {
        let data = vec![];
        assert_eq!(data.to_hex(), "");
    }

    #[test]
    fn test_to_hex_with_prefix_empty() {
        let data = vec![];
        assert_eq!(data.to_0x_hex(), "0x");
    }

    #[test]
    fn test_to_hex_from_slice() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(data[0..2].to_hex(), "0102");
    }

    #[test]
    fn test_to_hex_from_fixed_array() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(data.to_hex(), "01020304");
    }

    #[test]
    fn test_to_hex_with_prefix() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(data.to_0x_hex(), "0x01020304");
    }

    #[test]
    fn test_from_hex() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(Vec::from_hex("01020304").unwrap(), data);
    }

    #[test]
    fn test_from_hex_with_prefix() {
        let value = "0x01020304";
        assert_eq!(Vec::from_0x_hex(value).unwrap(), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_from_hex_with_prefix_error() {
        let value = "0x010203041";
        assert!(Vec::from_0x_hex(value).is_err(),);
    }

    #[test]
    fn test_from_hex_auto() {
        assert_eq!(
            Vec::from_hex_auto("0x01020304").unwrap(),
            [0x01, 0x02, 0x03, 0x04]
        );

        assert_eq!(
            Vec::from_hex_auto("01020304").unwrap(),
            [0x01, 0x02, 0x03, 0x04]
        );
    }
}
