use base58::{FromBase58, ToBase58};
use std::str::FromStr;
use tcx_common::CommonError;
use tcx_constants::CoinInfo;
use tcx_crypto::hash;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;

#[derive(PartialEq, Eq, Clone)]
pub struct EosAddress {
    pubkey_bytes: Vec<u8>,
    checksum: Vec<u8>,
}

impl Address for EosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<Self> {
        let pubkey_bytes = public_key.to_bytes();
        let hashed_bytes = hash::ripemd160(&pubkey_bytes);
        let checksum = hashed_bytes[..4].to_vec();

        Ok(EosAddress {
            pubkey_bytes,
            checksum,
        })
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let r = EosAddress::from_str(address);
        r.is_ok()
    }
}

impl FromStr for EosAddress {
    type Err = failure::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.starts_with("EOS") {
            let s = &s[3..];
            let bytes = s.from_base58().map_err(|_| CommonError::InvalidAddress)?;
            let checksum = bytes[bytes.len() - 4..].to_vec();
            let pubkey_bytes = bytes[..bytes.len() - 4].to_vec();

            let hashed_bytes = hash::ripemd160(&pubkey_bytes);
            let expected_checksum = hashed_bytes[..4].to_vec();
            if checksum != expected_checksum {
                return Err(CommonError::InvalidAddressChecksum.into());
            }

            Ok(EosAddress {
                pubkey_bytes,
                checksum,
            })
        } else {
            Err(CommonError::InvalidAddress.into())
        }
    }
}

impl ToString for EosAddress {
    fn to_string(&self) -> String {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.pubkey_bytes);
        bytes.extend_from_slice(&self.checksum);
        format!("EOS{}", bytes.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use crate::address::EosAddress;
    use std::str::FromStr;

    #[test]
    fn test_address() {
        let tests = [
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            "EOS5varo7aGmCFQw77DNiiWUj3YQA7ZmWUMC4NDDXeeaeEAXk436S",
            "EOS6w47YkvVGLzvKeozV5ZK34QApCmALrwoH2Dwhnirs5TZ9mg5io",
            "EOS5varo7aGmCFQw77DNiiWUj3YQA7ZmWUMC4NDDXeeaeEAXk436S",
        ];

        for i in tests {
            let addr = EosAddress::from_str(i).unwrap();
            assert_eq!(addr.to_string(), i);
        }
    }
}
