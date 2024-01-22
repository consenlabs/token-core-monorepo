use super::Result;

use crate::constant::SECP256K1_ENGINE;
use crate::ecc::{DeterministicPrivateKey, DeterministicPublicKey, KeyError};

use crate::{Derive, Secp256k1PrivateKey, Secp256k1PublicKey, Ss58Codec};
use tcx_common::{ripemd160, sha256, FromHex, ToHex};

use bitcoin::util::base58;
use bitcoin::util::base58::Error::InvalidLength;
use bitcoin::util::bip32::{
    ChainCode, ChildNumber, Error as Bip32Error, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
};
use bitcoin::Network;
use byteorder::BigEndian;
use byteorder::ByteOrder;

use bip39::{Language, Mnemonic};

#[derive(Clone)]
pub struct Bip32DeterministicPrivateKey(ExtendedPrivKey);

#[derive(Clone)]
pub struct Bip32DeterministicPublicKey(ExtendedPubKey);

impl From<Bip32Error> for KeyError {
    fn from(err: Bip32Error) -> Self {
        match err {
            Bip32Error::CannotDeriveFromHardenedKey => KeyError::CannotDeriveFromHardenedKey,
            Bip32Error::InvalidChildNumber(_) => KeyError::InvalidChildNumber,
            Bip32Error::InvalidChildNumberFormat => KeyError::InvalidChildNumberFormat,
            Bip32Error::InvalidDerivationPathFormat => KeyError::InvalidDerivationPathFormat,
            Bip32Error::Secp256k1(_) => KeyError::Secp256k1,
            Bip32Error::UnknownVersion(_) => KeyError::UnknownVersion,
            Bip32Error::WrongExtendedKeyLength(_) => KeyError::WrongExtendedKeyLength,
            Bip32Error::Base58(_) => KeyError::Base58,
            Bip32Error::Hex(_) => KeyError::Hex,
            _ => KeyError::NotImplement,
        }
    }
}

impl Bip32DeterministicPrivateKey {
    /// Construct a new master key from a seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let epk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
        Ok(Bip32DeterministicPrivateKey(epk))
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        let epk = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_ref())?;
        Ok(Bip32DeterministicPrivateKey(epk))
    }
}

impl Derive for Bip32DeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0;

        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }

        let children_nums = parts
            .map(str::parse)
            .collect::<std::result::Result<Vec<ChildNumber>, Bip32Error>>()?;
        let child_key = extended_key.derive_priv(&SECP256K1_ENGINE, &children_nums)?;

        Ok(Bip32DeterministicPrivateKey(child_key))
    }
}

impl Bip32DeterministicPublicKey {
    pub fn fingerprint(&self) -> Vec<u8> {
        let public_key_data = self.0.public_key.serialize();
        let hashed = ripemd160(&sha256(&public_key_data));
        hashed.to_vec()
    }
}

impl Derive for Bip32DeterministicPublicKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0;

        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }

        let children_nums = parts
            .map(str::parse)
            .collect::<std::result::Result<Vec<ChildNumber>, Bip32Error>>()?;
        let child_key = extended_key.derive_pub(&SECP256K1_ENGINE, &children_nums)?;

        Ok(Bip32DeterministicPublicKey(child_key))
    }
}

impl DeterministicPrivateKey for Bip32DeterministicPrivateKey {
    type DeterministicPublicKey = Bip32DeterministicPublicKey;
    type PrivateKey = Secp256k1PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
        let esk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)?;
        Ok(Bip32DeterministicPrivateKey(esk))
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        let esk = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes())?;

        Ok(Bip32DeterministicPrivateKey(esk))
    }

    fn private_key(&self) -> Self::PrivateKey {
        let btc_pk = bitcoin::PrivateKey::from_slice(
            self.0.private_key.secret_bytes().as_slice(),
            bitcoin::Network::Bitcoin,
        )
        .expect("generate private key error");
        Secp256k1PrivateKey::from(btc_pk)
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        let pk = ExtendedPubKey::from_priv(&SECP256K1_ENGINE, &self.0);
        Bip32DeterministicPublicKey(pk)
    }
}

impl DeterministicPublicKey for Bip32DeterministicPublicKey {
    type PublicKey = Secp256k1PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        Secp256k1PublicKey::from(
            bitcoin::PublicKey::from_slice(self.0.public_key.clone().serialize().as_slice())
                .expect("generate public key error"),
        )
    }
}

impl ToString for Bip32DeterministicPublicKey {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl ToString for Bip32DeterministicPrivateKey {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl ToHex for Bip32DeterministicPublicKey {
    fn to_hex(&self) -> String {
        let mut ret = [0; 74];
        let extended_key = self.0;
        ret[0] = extended_key.depth;
        ret[1..5].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[5..9], u32::from(extended_key.child_number));

        ret[9..41].copy_from_slice(&extended_key.chain_code[..]);
        ret[41..74].copy_from_slice(&extended_key.public_key.serialize()[..]);
        ret.to_hex()
    }
}

impl FromHex for Bip32DeterministicPublicKey {
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self> {
        let data = Vec::from_hex(hex)?;

        if data.len() != 74 {
            return Err(KeyError::InvalidBase58.into());
        }
        let cn_int: u32 = BigEndian::read_u32(&data[5..9]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: data[0],
            parent_fingerprint: Fingerprint::from(&data[1..5]),
            child_number,
            chain_code: ChainCode::from(&data[9..41]),
            public_key: secp256k1::PublicKey::from_slice(&data[41..74])?,
        };
        Ok(Bip32DeterministicPublicKey(epk))
    }
}

impl Ss58Codec for Bip32DeterministicPublicKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 78 {
            return Err(KeyError::InvalidBase58.into());
        }
        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = ExtendedPubKey {
            network: Network::Bitcoin,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        };

        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32DeterministicPublicKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 78];
        let extended_key = self.0;
        ret[0..4].copy_from_slice(version);
        ret[4] = extended_key.depth;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45..78].copy_from_slice(&extended_key.public_key.serialize()[..]);
        base58::check_encode_slice(&ret[..])
    }
}

impl Ss58Codec for Bip32DeterministicPrivateKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 78 {
            return Err(InvalidLength(data.len()).into());
        }

        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let network = Network::Bitcoin;
        let epk = ExtendedPrivKey {
            network,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        };
        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32DeterministicPrivateKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 78];
        let extended_key = &self.0;

        ret[0..4].copy_from_slice(version);
        ret[4] = extended_key.depth;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&extended_key.private_key[..]);
        base58::check_encode_slice(&ret[..])
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ecc::KeyError, Bip32DeterministicPrivateKey, Bip32DeterministicPublicKey, Derive,
        DeterministicPrivateKey, PrivateKey, Ss58Codec,
    };
    use bip39::{Language, Mnemonic, Seed};
    use bitcoin::util::{base58, bip32::Error as Bip32Error};
    use bitcoin_hashes::hex;
    use std::collections::HashMap;
    use tcx_common::{FromHex, ToHex};

    fn default_seed() -> Seed {
        let mn = Mnemonic::from_phrase(
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            Language::English,
        )
        .unwrap();
        Seed::new(&mn, "")
    }

    #[test]
    fn derive_public_keys() {
        let seed = default_seed();
        let paths = vec![
            "m/44'/0'/0'/0/0",
            "m/44'/0'/0'/0/1",
            "m/44'/0'/0'/1/0",
            "m/44'/0'/0'/1/1",
        ];
        let esk = Bip32DeterministicPrivateKey::from_seed(seed.as_bytes()).unwrap();
        let pub_keys = paths
            .iter()
            .map(|path| {
                esk.derive(path)
                    .unwrap()
                    .private_key()
                    .public_key()
                    .to_compressed()
                    .to_hex()
            })
            .collect::<Vec<String>>();
        let expected_pub_keys = vec![
            "026b5b6a9d041bc5187e0b34f9e496436c7bff261c6c1b5f3c06b433c61394b868",
            "024fb7df3961e08f01025e434ea19708a4317d2fe59775cddd38df6e8a2d30697d",
            "0352470ace48f25b01b9c341e3b0e033fc32a203fb7a81a0453f97d94eca819a35",
            "022f4c38f7bbaa00fc886db62f975b34201c2bfed146e98973caf03268941801db",
        ];
        assert_eq!(pub_keys, expected_pub_keys);
    }

    #[test]
    fn derive_keys() {
        let seed = default_seed();
        let root = Bip32DeterministicPrivateKey::from_seed(seed.as_bytes()).unwrap();

        let dpk = root
            .derive("m/44'/0'/0'")
            .unwrap()
            .deterministic_public_key();

        assert_eq!(dpk.to_string(), "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");

        let dsk = root.derive("m/44'/0'/0'").unwrap();

        assert_eq!(dsk.to_string(), "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ");
    }

    #[test]
    fn from_xpub() {
        let xpub = Bip32DeterministicPublicKey::from_ss58check_with_version("xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx");
        assert!(xpub.is_err());

        let xpub = Bip32DeterministicPublicKey::from_ss58check_with_version("xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");
        assert!(xpub.is_ok());
        assert_eq!(xpub.unwrap().0.to_hex(), "03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77");
    }

    #[test]
    fn from_hex() {
        let xpub = Bip32DeterministicPublicKey::from_ss58check_with_version("xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");
        assert!(xpub.is_ok());

        let r= Bip32DeterministicPublicKey::from_hex("03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af77").unwrap();
        assert_eq!(r.to_string(), "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8");
    }

    #[test]
    fn test_from_hex_invalid_base58() {
        let actual = Bip32DeterministicPublicKey::from_hex("03a25f12b68000000044efc688fe25a1a677765526ed6737b4bfcfb0122589caab7ca4b223ffa9bb37029d23439ecb195eb06a0d44a608960d18702fd97e19c53451f0548f568207af");
        assert_eq!(
            actual.err().unwrap().to_string(),
            KeyError::InvalidBase58.to_string()
        );
    }

    #[test]
    fn export_and_import() {
        let dpks= [
           "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8",
           "tpubDCpWeoTY6x4BR2PqoTFJnEdfYbjnC4G8VvKoDUPFjt2dvZJWkMRxLST1pbVW56P7zY3L5jq9MRSeff2xsLnvf9qBBN9AgvrhwfZgw5dJG6R",
           "tpubDEbvpFLnzUaeKimACznAJmoi8JDktEudB7EK4BnJFD4jTBqxBprwZrBAEEVrSZbEL2nFELm7cH6o81z9FQ3nwrSR7Rebj4jxGFsB5BLq1EY",
           "xpub6Bs32Yr5Phs3gB6rdNrG4az7Jgr1YKGmKXSV8i4Py4mKd7jUzag8EN6u2gTN1dYHshgL3AmJM6n1enwR1dUnQUr8nDG23G22oDtzGRopACX",
           "vpub5ZbhUa5EheCJVJLskohSBEyL1qSAxZpMNCN36aQeHHt1jndkpeeiV48YHNiQGafTu5dPZz5e1RyjHzWu8vpAj4vixVUt1rhkrFJR8Fp2EF1"
        ];

        for dpk in dpks.iter() {
            let (dpk, _) = Bip32DeterministicPublicKey::from_ss58check_with_version(dpk).unwrap();
            let hex = dpk.to_hex();
            let dpk2 = Bip32DeterministicPublicKey::from_hex(&hex).unwrap();
            assert_eq!(dpk.to_string(), dpk2.to_string());
        }
    }

    #[test]
    fn test_key_error_from() {
        let key_error = KeyError::from(Bip32Error::CannotDeriveFromHardenedKey);
        assert_eq!(key_error, KeyError::CannotDeriveFromHardenedKey);
        let key_error = KeyError::from(Bip32Error::InvalidChildNumber(0));
        assert_eq!(key_error, KeyError::InvalidChildNumber);
        let key_error = KeyError::from(Bip32Error::InvalidChildNumberFormat);
        assert_eq!(key_error, KeyError::InvalidChildNumberFormat);
        let key_error = KeyError::from(Bip32Error::InvalidDerivationPathFormat);
        assert_eq!(key_error, KeyError::InvalidDerivationPathFormat);
        let key_error = KeyError::from(Bip32Error::Secp256k1(secp256k1::Error::InvalidPublicKey));
        assert_eq!(key_error, KeyError::Secp256k1);
        let key_error = KeyError::from(Bip32Error::UnknownVersion([0; 4]));
        assert_eq!(key_error, KeyError::UnknownVersion);
        let key_error = KeyError::from(Bip32Error::WrongExtendedKeyLength(0));
        assert_eq!(key_error, KeyError::WrongExtendedKeyLength);
        let key_error = KeyError::from(Bip32Error::Base58(base58::Error::InvalidLength(0)));
        assert_eq!(key_error, KeyError::Base58);
        let key_error = KeyError::from(Bip32Error::Hex(hex::Error::InvalidChar(0)));
        assert_eq!(key_error, KeyError::Hex);
    }

    #[test]
    fn test_bip32_spec_vectors() {
        let test_data1 = vec![
            ("m", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
            ("m/0'", "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
            ("m/0'/1", "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
            ("m/0'/1/2'", "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
            ("m/0'/1/2'/2", "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
            ("m/0'/1/2'/2/1000000000", "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
        ];
        let test_data2 = vec![
            ("m", "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"),
            ("m/0", "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"),
            ("m/0/2147483647'", "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"),
            ("m/0/2147483647'/1", "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"),
            ("m/0/2147483647'/1/2147483646'", "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"),
            ("m/0/2147483647'/1/2147483646'/2", "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"),
        ];
        let test_data3 = vec![
            ("m", "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"),
            ("m/0'", "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"),
        ];
        let test_data4 = vec![
            ("m", "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv", "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"),
            ("m/0'", "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G", "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"),
            ("m/0'/1'", "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1", "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"),
        ];
        let mut test_data = HashMap::new();
        test_data.insert("000102030405060708090a0b0c0d0e0f", test_data1);
        test_data.insert("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", test_data2);
        test_data.insert("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", test_data3);
        test_data.insert(
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            test_data4,
        );
        for data_list in test_data.iter() {
            let seed = Vec::from_hex(data_list.0).unwrap();
            let pri_key = Bip32DeterministicPrivateKey::from_seed(&seed).unwrap();
            for data in data_list.1.iter().enumerate() {
                let pri_key = Bip32DeterministicPrivateKey::from_seed(&seed).unwrap();
                if data.0 == 0 && "m".eq(data.1 .0) {
                    assert_eq!(pri_key.to_string(), data.1 .1);
                    assert_eq!(pri_key.deterministic_public_key().to_string(), data.1 .2);
                    continue;
                }
                let pri_key = pri_key.derive(data.1 .0).unwrap();
                let pub_key = pri_key.deterministic_public_key();
                assert_eq!(pri_key.to_string(), data.1 .1);
                assert_eq!(pub_key.to_string(), data.1 .2);
            }
        }
    }
}
