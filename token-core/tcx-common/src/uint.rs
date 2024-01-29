use crate::Result;
use ethereum_types::{U256, U64};

pub fn parse_u64(number: &str) -> Result<U64> {
    if number.to_lowercase().starts_with("0x") {
        Ok(U64::from_str_radix(&number[2..], 16)?)
    } else {
        Ok(U64::from_dec_str(number)?)
    }
}

pub fn parse_u256(number: &str) -> Result<U256> {
    if number.to_lowercase().starts_with("0x") {
        Ok(U256::from_str_radix(&number[2..], 16)?)
    } else {
        Ok(U256::from_dec_str(number)?)
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::{U256, U64};
    #[test]
    fn test_parse_u64() {
        assert_eq!(super::parse_u64("0xff").unwrap(), U64::from(255u64));
        assert_eq!(super::parse_u64("1234567").unwrap(), U64::from(1234567));
        assert_eq!(super::parse_u64("").unwrap(), U64::from(0));
        assert!(super::parse_u64("/").is_err());
    }

    #[test]
    fn test_parse_u256() {
        assert_eq!(super::parse_u256("0xff").unwrap(), U256::from(255u64));
        assert_eq!(super::parse_u256("1234567").unwrap(), U256::from(1234567));
    }
}
