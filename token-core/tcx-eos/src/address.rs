use base58::ToBase58;
use failure::format_err;
use regex::Regex;
use tcx_chain::Keystore;
use tcx_chain::{tcx_ensure, Address, ChainFactory, PublicKeyEncoder, Result};
use tcx_constants::CoinInfo;
use tcx_crypto::hash;
use tcx_primitive::{PublicKey, Secp256k1PublicKey, TypedPublicKey};

pub struct EosAddress();

impl Address for EosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        // EOS address is registered by user, not from public key
        Ok("".to_string())
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        let re = Regex::new(r"^[1-5a-z.]{1,12}$").expect("eos account regex");

        re.is_match(address)
    }
}

pub struct EosPublicKeyEncoder();

impl PublicKeyEncoder for EosPublicKeyEncoder {
    fn encode(&self, public_key: &[u8]) -> Result<String> {
        let compressed_pub_key = Secp256k1PublicKey::from_slice(public_key)?.to_compressed();
        let bytes = compressed_pub_key.as_slice();
        let hashed_bytes = hash::ripemd160(&bytes);
        let checksum = &hashed_bytes[..4];
        Ok(format!("EOS{}", [&bytes, checksum].concat().to_base58()))
    }
}

pub struct EosChainFactory();
impl ChainFactory for EosChainFactory {
    fn create_public_key_encoder(&self) -> Box<dyn PublicKeyEncoder> {
        Box::new(EosPublicKeyEncoder {})
    }
}

pub fn eos_update_account(ks: &mut Keystore, account_name: &str) -> tcx_chain::Result<()> {
    tcx_ensure!(
        EosAddress::is_valid(account_name, &CoinInfo::default()),
        format_err!("eos_account_name_invalid")
    );
    let store = ks.store_mut();
    let acc = store
        .active_accounts
        .iter_mut()
        .find(|acc| acc.coin == "EOS");
    if let Some(acc) = acc {
        acc.address = account_name.to_string();
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::address::{EosAddress, EosChainFactory};
    use tcx_chain::{Address, ChainFactory, PublicKeyEncoder};

    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{
        PrivateKey, PublicKey, Secp256k1PrivateKey, Secp256k1PublicKey, TypedPublicKey,
    };

    use super::EosPublicKeyEncoder;

    fn get_test_coin() -> CoinInfo {
        CoinInfo {
            coin: "EOS".to_string(),
            derivation_path: "m/44'/194'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "".to_string(),
            seg_wit: "".to_string(),
        }
    }

    #[test]
    fn test_address_is_valid() {
        let invalid_addresses = vec!["accountnameaccountname", "accountname6", "AccountName"];
        for addr in invalid_addresses {
            assert!(!EosAddress::is_valid(addr, &get_test_coin()), "{}", addr);
        }

        let valid_addresses = vec!["imtoken.1111", "accountname1"];
        for addr in valid_addresses {
            assert!(EosAddress::is_valid(addr, &get_test_coin()));
        }
    }

    #[test]
    fn test_encode_public_key() {
        let sec_key =
            Secp256k1PrivateKey::from_wif("5KAigHMamRhN7uwHFnk3yz7vUTyQT1nmXoAA899XpZKJpkqsPFp")
                .unwrap();
        let eos_factory = EosChainFactory {};
        let encoder = eos_factory.create_public_key_encoder();
        let pub_key = sec_key.public_key();
        let pub_key_str = encoder.encode(&pub_key.to_bytes()).unwrap();
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            pub_key_str
        );
    }
}
