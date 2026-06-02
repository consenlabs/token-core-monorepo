use bitcoin::base58;
use bitcoin::bip32::{ChainCode, ChildNumber, Error as BitcoinBip32Error, Fingerprint, Xpub};
use bitcoin::secp256k1;
use bitcoin::Network;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum XpubError {
    InvalidBase58,
    Base58(base58::Error),
    Bip32(BitcoinBip32Error),
    Secp256k1(secp256k1::Error),
}

impl fmt::Display for XpubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XpubError::InvalidBase58 => f.write_str("invalid_base58"),
            XpubError::Base58(err) => err.fmt(f),
            XpubError::Bip32(err) => err.fmt(f),
            XpubError::Secp256k1(err) => err.fmt(f),
        }
    }
}

impl Error for XpubError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            XpubError::InvalidBase58 => None,
            XpubError::Base58(err) => Some(err),
            XpubError::Bip32(err) => Some(err),
            XpubError::Secp256k1(err) => Some(err),
        }
    }
}

impl From<base58::Error> for XpubError {
    fn from(err: base58::Error) -> Self {
        XpubError::Base58(err)
    }
}

impl From<BitcoinBip32Error> for XpubError {
    fn from(err: BitcoinBip32Error) -> Self {
        XpubError::Bip32(err)
    }
}

impl From<secp256k1::Error> for XpubError {
    fn from(err: secp256k1::Error) -> Self {
        XpubError::Secp256k1(err)
    }
}

pub fn xpub_to_ss58check_with_version(extended_key: &Xpub, version: &[u8]) -> String {
    let mut ret = [0; 78];
    ret[0..4].copy_from_slice(version);
    ret[4] = extended_key.depth;
    ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);
    ret[9..13].copy_from_slice(&u32::from(extended_key.child_number).to_be_bytes());
    ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
    ret[45..78].copy_from_slice(&extended_key.public_key.serialize()[..]);
    base58::encode_check(&ret[..])
}

pub fn xpub_from_ss58check_with_version(s: &str) -> Result<(Xpub, Vec<u8>), XpubError> {
    let data = base58::decode_check(s)?;

    if data.len() != 78 {
        return Err(XpubError::InvalidBase58);
    }

    let child_number = ChildNumber::from(u32::from_be_bytes(
        data[9..13].try_into().expect("slice length checked"),
    ));
    let epk = Xpub {
        network: Network::Bitcoin.into(),
        depth: data[4],
        parent_fingerprint: Fingerprint::from(<[u8; 4]>::try_from(&data[5..9]).unwrap()),
        child_number,
        chain_code: ChainCode::from(<[u8; 32]>::try_from(&data[13..45]).unwrap()),
        public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
    };

    Ok((epk, data[0..4].to_vec()))
}

pub fn derive_xpub(extended_pub_key: &Xpub, path: &str) -> Result<Xpub, XpubError> {
    let mut parts = path.split('/').peekable();
    if *parts.peek().unwrap() == "m" {
        parts.next();
    }

    let children_nums = parts
        .map(str::parse)
        .collect::<Result<Vec<ChildNumber>, BitcoinBip32Error>>()?;
    let secp = secp256k1::Secp256k1::new();
    Ok(extended_pub_key.derive_pub(&secp, &children_nums)?)
}

pub fn bitcoin_network_from_name(network: &str) -> Network {
    match network.to_uppercase().as_str() {
        "MAINNET" => Network::Bitcoin,
        "TESTNET" => Network::Testnet,
        _ => Network::Testnet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;

    #[test]
    fn round_trips_xpub_with_version() {
        let seed = [1u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let version = [0x04, 0x88, 0xb2, 0x1e];

        let encoded = xpub_to_ss58check_with_version(&xpub, &version);
        let (decoded, decoded_version) = xpub_from_ss58check_with_version(&encoded).unwrap();

        assert_eq!(decoded.public_key, xpub.public_key);
        assert_eq!(decoded_version, version);
    }
}
