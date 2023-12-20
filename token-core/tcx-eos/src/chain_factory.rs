use base58::ToBase58;
use tcx_common::ripemd160;
use tcx_keystore::{ChainFactory, PrivateKeyEncoder, PublicKeyEncoder, Result};
use tcx_primitive::{PrivateKey, PublicKey, Secp256k1PrivateKey, Secp256k1PublicKey, Ss58Codec};

pub struct EosPublicKeyEncoder();

impl PublicKeyEncoder for EosPublicKeyEncoder {
    fn encode(&self, public_key: &[u8]) -> Result<String> {
        let compressed_pub_key = Secp256k1PublicKey::from_slice(public_key)?.to_compressed();
        let bytes = compressed_pub_key.as_slice();
        let hashed_bytes = ripemd160(&bytes);
        let checksum = &hashed_bytes[..4];
        Ok(format!("EOS{}", [&bytes, checksum].concat().to_base58()))
    }
}

pub struct EosPrivateKeyEncoder();

const VERSION: u8 = 0x80;

impl PrivateKeyEncoder for EosPrivateKeyEncoder {
    fn encode(&self, bytes: &[u8]) -> Result<String> {
        let mut private_key = Secp256k1PrivateKey::from_slice(bytes)?;
        // EOS need export uncompressed wif
        private_key.0.compressed = false;
        Ok(private_key.to_ss58check_with_version(&[VERSION]))
    }

    fn decode(&self, wif: &str) -> Result<Vec<u8>> {
        let private_key = Secp256k1PrivateKey::from_wif(wif)?;
        Ok(private_key.to_bytes())
    }
}
// pub struct EosChainFactory();

// impl Default for EosChainFactory {
//     fn default() -> Self {
//         EosChainFactory()
//     }
// }

// impl ChainFactory for EosChainFactory {
//     fn create_public_key_encoder(&self) -> Box<dyn PublicKeyEncoder> {
//         Box::new(EosPublicKeyEncoder {})
//     }
// }

#[cfg(test)]
mod tests {

    use crate::{address::EosAddress, EosChainFactory};
    use tcx_common::ToHex;
    use tcx_keystore::{ChainFactory, HdKeystore, Keystore, Metadata, PrivateKeyEncoder};

    use tcx_constants::{sample_key::MNEMONIC, CoinInfo, CurveType, TEST_PASSWORD};
    use tcx_primitive::{PrivateKey, PublicKey, Secp256k1PrivateKey};

    use super::EosPrivateKeyEncoder;

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
    fn test_encode_public_key() {
        let sec_key =
            Secp256k1PrivateKey::from_wif("5KAigHMamRhN7uwHFnk3yz7vUTyQT1nmXoAA899XpZKJpkqsPFp")
                .unwrap();
        let eos_factory = EosChainFactory::default();
        let encoder = eos_factory.create_public_key_encoder();
        let pub_key = sec_key.public_key();
        let pub_key_str = encoder.encode(&pub_key.to_bytes()).unwrap();
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            pub_key_str
        );
    }

    #[test]
    fn test_private_key_encoder_decode() {
        let mut keystore = Keystore::Hd(
            HdKeystore::from_mnemonic(MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap(),
        );
        let coin_info = &get_test_coin();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        keystore.derive_coin::<EosAddress>(coin_info).unwrap();

        let private_key_bytes = keystore
            .get_private_key(coin_info.curve, &coin_info.derivation_path)
            .unwrap()
            .to_bytes();

        let ss_58_private_key = EosPrivateKeyEncoder()
            .encode(private_key_bytes.as_slice())
            .unwrap();
        assert_eq!(
            ss_58_private_key,
            "5KAigHMamRhN7uwHFnk3yz7vUTyQT1nmXoAA899XpZKJpkqsPFp"
        );

        let private_key_bytes = EosPrivateKeyEncoder()
            .decode(ss_58_private_key.as_str())
            .unwrap();
        assert_eq!(
            private_key_bytes.to_0x_hex(),
            "0xb2174e5eecbbd06fd4f4d0a910275d12f151e66efbdbe4e548b0d0846b882509"
        );
    }
}
