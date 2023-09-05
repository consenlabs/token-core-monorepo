use core::fmt;

use core::result;
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use bitcoin::hash_types::PubkeyHash as PubkeyHashType;
use bitcoin::hash_types::ScriptHash as ScriptHashType;
use bitcoin::network::constants::Network;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::address::Payload;
use bitcoin::util::address::{Error as LibAddressError, WitnessVersion};
use bitcoin::util::base58;
use bitcoin::util::key::PublicKey;
use bitcoin::{Address as LibAddress, Script};
use bitcoin_hashes::Hash;
use secp256k1::Secp256k1;

use tcx_chain::Address;
use tcx_constants::CoinInfo;
use tcx_primitive::{Ss58Codec, TypedPrivateKey, TypedPublicKey};

use crate::network::BtcKinNetwork;
use crate::Error;
use crate::Result;

pub trait WIFDisplay {
    fn fmt(&self, coin_info: &CoinInfo) -> Result<String>;
}

pub trait ScriptPubkey {
    fn script_pubkey(&self) -> Script;
}

impl WIFDisplay for TypedPrivateKey {
    fn fmt(&self, coin_info: &CoinInfo) -> Result<String> {
        let network = BtcKinNetwork::find_by_coin(&coin_info.coin, &coin_info.network);
        tcx_ensure!(network.is_some(), Error::UnsupportedChain);

        let key = self.as_secp256k1()?;
        let version = vec![network.unwrap().private_prefix];
        Ok(key.to_ss58check_with_version(&version))
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtcKinAddress {
    pub network: BtcKinNetwork,
    pub payload: Payload,
}

impl Address for BtcKinAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let network = BtcKinNetwork::find_by_coin(&coin.coin, &coin.network);
        tcx_ensure!(network.is_some(), Error::MissingNetwork);
        let network = network.expect("network");

        let address = match coin.seg_wit.as_str() {
            "P2WPKH" => BtcKinAddress::p2shwpkh(&public_key.to_bytes(), &network)?,
            "SEGWIT" => BtcKinAddress::p2wpkh(&public_key.to_bytes(), &network)?,
            "P2TR" => BtcKinAddress::p2tr(&public_key.to_bytes(), &network)?,
            _ => BtcKinAddress::p2pkh(&public_key.to_bytes(), &network)?,
        };

        Ok(address)
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let ret = BtcKinAddress::from_str(address);
        if ret.is_err() {
            false
        } else {
            let addr: BtcKinAddress = ret.unwrap();
            addr.network.network == coin.network
        }
    }
}

impl BtcKinAddress {
    pub fn p2pkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(&pub_key)?;
        let addr = LibAddress::p2pkh(&pub_key, Network::Bitcoin);

        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2shwpkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(&pub_key)?;
        let addr = LibAddress::p2shwpkh(&pub_key, Network::Bitcoin)?;

        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2wpkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(&pub_key)?;
        let addr = LibAddress::p2wpkh(&pub_key, Network::Bitcoin)?;
        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2tr(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = UntweakedPublicKey::from(secp256k1::PublicKey::from_slice(&pub_key)?);
        let secp256k1 = Secp256k1::new();
        let addr = LibAddress::p2tr(&secp256k1, pub_key, None, Network::Bitcoin);
        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn script_pubkey(&self) -> Script {
        self.payload.script_pubkey()
    }

    pub fn extended_public_key(
        derivation_info: &impl Ss58Codec,
        coin_info: &CoinInfo,
    ) -> Result<String> {
        let network = BtcKinNetwork::find_by_coin(&coin_info.coin, &coin_info.network);
        tcx_ensure!(network.is_some(), Error::UnsupportedChain);
        Ok(derivation_info.to_ss58check_with_version(&network.unwrap().xpub_prefix))
    }

    pub fn extended_private_key(
        extended_priv_key: &impl Ss58Codec,
        coin_info: &CoinInfo,
    ) -> Result<String> {
        let network = BtcKinNetwork::find_by_coin(&coin_info.coin, &coin_info.network);
        tcx_ensure!(network.is_some(), Error::UnsupportedChain);
        Ok(extended_priv_key.to_ss58check_with_version(&network.unwrap().xprv_prefix))
    }
}

/// Extract the bech32 prefix.
/// Returns the same slice when no prefix is found.
fn bech32_network(bech32: &str) -> Option<&BtcKinNetwork> {
    let bech32_prefix = match bech32.rfind('1') {
        None => None,
        Some(sep) => Some(bech32.split_at(sep).0),
    };

    match bech32_prefix {
        Some(prefix) => BtcKinNetwork::find_by_hrp(prefix),
        None => None,
    }
}

fn decode_base58(addr: &str) -> result::Result<Vec<u8>, LibAddressError> {
    // Base58
    if addr.len() > 50 {
        return Err(LibAddressError::Base58(base58::Error::InvalidLength(
            addr.len() * 11 / 15,
        )));
    }
    let data = base58::from_check(&addr)?;
    if data.len() != 21 {
        Err(LibAddressError::Base58(base58::Error::InvalidLength(
            data.len(),
        )))
    } else {
        Ok(data)
    }
}

impl ScriptPubkey for BtcKinAddress {
    fn script_pubkey(&self) -> Script {
        self.script_pubkey()
    }
}

impl FromStr for BtcKinAddress {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<BtcKinAddress> {
        // try bech32
        let bech32_network = bech32_network(s);
        if let Some(network) = bech32_network {
            // decode as bech32
            let (_, payload, _) = bech32::decode(s)?;
            if payload.is_empty() {
                return Err(LibAddressError::EmptyBech32Payload.into());
            }

            // Get the script version and program (converted from 5-bit to 8-bit)
            let (version, program): (bech32::u5, Vec<u8>) = {
                let (v, p5) = payload.split_at(1);
                (v[0], bech32::FromBase32::from_base32(p5)?)
            };

            // Generic segwit checks.
            if version.to_u8() > 16 {
                return Err(LibAddressError::InvalidWitnessVersion(version.to_u8()).into());
            }
            if program.len() < 2 || program.len() > 40 {
                return Err(LibAddressError::InvalidWitnessProgramLength(program.len()).into());
            }

            // Specific segwit v0 check.
            if version.to_u8() == 0 && (program.len() != 20 && program.len() != 32) {
                return Err(LibAddressError::InvalidSegwitV0ProgramLength(program.len()).into());
            }
            let payload = Payload::WitnessProgram {
                version: WitnessVersion::try_from(version.to_u8())?,
                program,
            };
            return Ok(BtcKinAddress {
                payload,
                network: network.clone(),
            });
        }

        let data = decode_base58(s)?;
        if let Some(network) = BtcKinNetwork::find_by_prefix(data[0]) {
            if network.p2pkh_prefix == data[0] {
                return Ok(BtcKinAddress {
                    network: network.clone(),
                    payload: Payload::PubkeyHash(PubkeyHashType::from_slice(&data[1..]).unwrap()),
                });
            } else if network.p2sh_prefix == data[0] {
                return Ok(BtcKinAddress {
                    network: network.clone(),
                    payload: Payload::ScriptHash(ScriptHashType::from_slice(&data[1..]).unwrap()),
                });
            }
        }

        Err(LibAddressError::UnrecognizedScript.into())
    }
}

struct UpperWriter<W: fmt::Write>(W);

impl<W: fmt::Write> fmt::Write for UpperWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.0.write_char(c.to_ascii_uppercase())?;
        }
        Ok(())
    }
}

impl Display for BtcKinAddress {
    fn fmt(&self, fmt: &mut Formatter) -> core::fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::WitnessProgram {
                version,
                program: ref prog,
            } => {
                let mut upper_writer;
                let writer = if fmt.alternate() {
                    upper_writer = UpperWriter(fmt);
                    &mut upper_writer as &mut dyn fmt::Write
                } else {
                    fmt as &mut dyn fmt::Write
                };
                let mut bech32_writer = bech32::Bech32Writer::new(
                    &self.network.bech32_hrp,
                    version.bech32_variant(),
                    writer,
                )?;
                bech32::WriteBase32::write_u5(&mut bech32_writer, version.into())?;
                bech32::ToBase32::write_base32(&prog, &mut bech32_writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{Bip32DeterministicPrivateKey, Derive, DeterministicPrivateKey, Ss58Codec};

    use crate::address::BtcKinAddress;
    use crate::tcx_chain::Address;
    use crate::BtcKinNetwork;

    #[test]
    pub fn test_btc_kin_address() {
        let pub_key_str = "02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba";
        let pub_key = hex::decode(pub_key_str).unwrap();
        let network = BtcKinNetwork::find_by_coin("LITECOIN", "MAINNET").unwrap();
        let addr = BtcKinAddress::p2shwpkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW");

        let network = BtcKinNetwork::find_by_coin("LITECOIN", "MAINNET").unwrap();
        let addr = BtcKinAddress::p2wpkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "ltc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdn08yddf");

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let addr = BtcKinAddress::p2shwpkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG");

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let addr = BtcKinAddress::p2wpkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "bc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdntm7f4e");
    }

    #[test]
    pub fn test_btc_kin_address_from_str() {
        let addr = BtcKinAddress::from_str("MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW").unwrap();
        assert_eq!(addr.network.coin, "LITECOIN");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcKinAddress::from_str("ltc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdn08yddf").unwrap();
        assert_eq!(addr.network.coin, "LITECOIN");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcKinAddress::from_str("3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcKinAddress::from_str("bc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdntm7f4e").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcKinAddress::from_str("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcKinAddress::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.network, "TESTNET");
    }

    #[test]
    pub fn test_extended_private_key() {
        let bitcoin_xprv_str = "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ";
        let anprv = Bip32DeterministicPrivateKey::from_ss58check(bitcoin_xprv_str).unwrap();
        let coin_info = CoinInfo {
            coin: "LITECOIN".to_string(),
            derivation_path: "m/44'/2'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let ltc_xprv_str = BtcKinAddress::extended_private_key(&anprv, &coin_info).unwrap();
        assert_eq!("xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ", ltc_xprv_str);
    }

    #[test]
    pub fn test_extended_public_key() {
        let bitcoin_xprv_str = "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ";
        let anpub = Bip32DeterministicPrivateKey::from_ss58check(bitcoin_xprv_str)
            .unwrap()
            .derive("m/44'/2'/0'")
            .unwrap()
            .deterministic_public_key();
        let coin_info = CoinInfo {
            coin: "LITECOIN".to_string(),
            derivation_path: "m/44'/2'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let ltc_xprv_str = BtcKinAddress::extended_public_key(&anpub, &coin_info).unwrap();
        assert_eq!("xpub6JeaAjhtvtjCDnEo4Bjr7uEbGccaHnJtLY4aBnMaAYGjkBRB3fP9XvjcCbNjMiU1n5tt7dYKVgHPGzh3t3W6eLBxavxABTaoQ2jhbiQrfe4", ltc_xprv_str);
    }

    #[test]
    pub fn test_script_pubkey() {
        let addr = BtcKinAddress::from_str("MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW").unwrap();
        let script = hex::encode(addr.script_pubkey().as_bytes());
        assert_eq!("a914bc64b2d79807cd3d72101c3298b89117d32097fb87", script);

        let addr = BtcKinAddress::from_str("ltc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdn08yddf").unwrap();
        let script = hex::encode(addr.script_pubkey().as_bytes());
        assert_eq!("0014e6cfaab9a59ba187f0a45db0b169c21bb48f09b3", script);

        let addr = BtcKinAddress::from_str("Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP").unwrap();
        let script = hex::encode(addr.script_pubkey().as_bytes());
        assert_eq!("76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac", script);

        let addr = BtcKinAddress::from_str("3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG").unwrap();
        let script = hex::encode(addr.script_pubkey().as_bytes());
        assert_eq!("a914bc64b2d79807cd3d72101c3298b89117d32097fb87", script);
    }

    #[test]
    pub fn test_address_valid() {
        let coin = coin_info_from_param("BITCOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG",
            &coin
        ));

        let coin = coin_info_from_param("BITCOIN", "MAINNET", "NONE", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "1Gx9QwpQBFnAjF27Uiz3ea2zYBDrLx31bw",
            &coin
        ));

        let coin = coin_info_from_param("BITCOIN", "MAINNET", "SEGWIT", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "bc1qnfv46v0wtarc6n82dnehtvzj2gtnqzjhj5wxqj",
            &coin
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "NONE", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP",
            &coin
        ));
        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW",
            &coin
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(!BtcKinAddress::is_valid(
            "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDf",
            &coin
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(!BtcKinAddress::is_valid("aaa", &coin));
    }
}
