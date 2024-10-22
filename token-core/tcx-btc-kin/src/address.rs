use core::result;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
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

use tcx_constants::CoinInfo;
use tcx_keystore::Address;
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
        let network = network.unwrap();

        let address = match coin.seg_wit.as_str() {
            "P2WPKH" => BtcKinAddress::p2shwpkh(&public_key.to_bytes(), network)?,
            "VERSION_0" => BtcKinAddress::p2wpkh(&public_key.to_bytes(), network)?,
            "VERSION_1" => BtcKinAddress::p2tr(&public_key.to_bytes(), network)?,
            _ => BtcKinAddress::p2pkh(&public_key.to_bytes(), network)?,
        };

        Ok(address)
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let ret = BtcKinAddress::from_str(address);
        if let Ok(btc_kin_addr) = ret {
            btc_kin_addr.network.network == coin.network
        } else {
            false
        }
    }
}

impl BtcKinAddress {
    pub fn p2pkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(pub_key)?;
        let addr = LibAddress::p2pkh(&pub_key, Network::Bitcoin);

        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2shwpkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(pub_key)?;
        let addr = LibAddress::p2shwpkh(&pub_key, Network::Bitcoin)?;

        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2wpkh(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = PublicKey::from_slice(pub_key)?;
        let addr = LibAddress::p2wpkh(&pub_key, Network::Bitcoin)?;
        Ok(BtcKinAddress {
            payload: addr.payload,
            network: network.clone(),
        })
    }

    pub fn p2tr(pub_key: &[u8], network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let pub_key = UntweakedPublicKey::from(secp256k1::PublicKey::from_slice(pub_key)?);
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

fn bech32_network(bech32: &str) -> Option<&BtcKinNetwork> {
    let bech32_prefix = bech32.rfind('1').map(|sep| bech32.split_at(sep).0);

    if bech32_prefix.is_some() {
        let prefix = bech32_prefix.unwrap();
        if (!prefix.is_empty()) {
            return BtcKinNetwork::find_by_hrp(prefix);
        }
    }
    return None;
}

fn decode_base58(addr: &str) -> result::Result<Vec<u8>, LibAddressError> {
    // Base58
    if addr.len() > 50 {
        return Err(LibAddressError::Base58(base58::Error::InvalidLength(
            addr.len() * 11 / 15,
        )));
    }
    let data = base58::from_check(addr)?;
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
    type Err = anyhow::Error;

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

        let data = decode_base58(s).map_err(|_| Error::InvalidAddress)?;
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
                let mut bech32_writer = bech32::Bech32Writer::new(
                    self.network.bech32_hrp,
                    version.bech32_variant(),
                    fmt,
                )?;
                bech32::WriteBase32::write_u5(&mut bech32_writer, version.into())?;
                bech32::ToBase32::write_base32(&prog, &mut bech32_writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::SchnorrSighashType::Default;
    use secp256k1::rand::seq::index::sample;
    use std::str::FromStr;
    use tcx_common::{FromHex, ToHex};

    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{
        Bip32DeterministicPrivateKey, Derive, DeterministicPrivateKey, Ss58Codec, TypedPrivateKey,
        TypedPublicKey,
    };

    use crate::address::BtcKinAddress;
    use crate::tcx_keystore::Address;
    use crate::tests::sample_hd_keystore;
    use crate::BtcKinNetwork;

    #[test]
    fn test_btc_kin_address() {
        let pub_key_str = "02506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba";
        let pub_key = Vec::from_hex(pub_key_str).unwrap();
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

        let network = BtcKinNetwork::find_by_coin("DOGECOIN", "MAINNET").unwrap();
        let addr = BtcKinAddress::p2pkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "DSBWjKzZtz7fPzu4N6mBRwQFHCQ6KQSjue");

        let network = BtcKinNetwork::find_by_coin("DOGECOIN", "TESTNET").unwrap();
        let addr = BtcKinAddress::p2pkh(&pub_key, &network)
            .unwrap()
            .to_string();
        assert_eq!(addr, "nqEaTLjUpxaPGyUFPvQdgLzYX4nPLCD1Py");
    }

    #[test]
    fn test_btc_kin_address_from_str() {
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
    fn test_extended_private_key() {
        let bitcoin_xprv_str = "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ";
        let anprv = Bip32DeterministicPrivateKey::from_ss58check(bitcoin_xprv_str).unwrap();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
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
    fn test_extended_public_key() {
        let bitcoin_xprv_str = "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ";
        let anpub = Bip32DeterministicPrivateKey::from_ss58check(bitcoin_xprv_str)
            .unwrap()
            .derive("m/44'/2'/0'")
            .unwrap()
            .deterministic_public_key();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
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
    fn test_script_pubkey() {
        let addr = BtcKinAddress::from_str("MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW").unwrap();
        let script = addr.script_pubkey().as_bytes().to_hex();
        assert_eq!("a914bc64b2d79807cd3d72101c3298b89117d32097fb87", script);

        let addr = BtcKinAddress::from_str("ltc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdn08yddf").unwrap();
        let script = addr.script_pubkey().as_bytes().to_hex();
        assert_eq!("0014e6cfaab9a59ba187f0a45db0b169c21bb48f09b3", script);

        let addr = BtcKinAddress::from_str("Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP").unwrap();
        let script = addr.script_pubkey().as_bytes().to_hex();
        assert_eq!("76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac", script);

        let addr = BtcKinAddress::from_str("3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG").unwrap();
        let script = addr.script_pubkey().as_bytes().to_hex();
        assert_eq!("a914bc64b2d79807cd3d72101c3298b89117d32097fb87", script);
    }

    #[test]
    fn test_invalid_address() {
        //Bad base58 checksum
        let r = BtcKinAddress::from_str("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo3");
        assert_eq!(r.err().unwrap().to_string(), "invalid_address");

        let r = BtcKinAddress::from_str("4MfAagS5MczC4DjH6RdV26nekvuXmhfBJq5MBWzv7nBnB73DMjst2");
        assert_eq!(r.err().unwrap().to_string(), "invalid_address");

        let r = BtcKinAddress::from_str("A8VLkJpStiaMXS3bTm3iHC58uDwoCHwCZpL");
        assert_eq!(r.err().unwrap().to_string(), "invalid_address");
    }

    #[test]
    fn test_address_valid() {
        let coin = coin_info_from_param("BITCOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG",
            &coin,
        ));

        let coin = coin_info_from_param("BITCOIN", "MAINNET", "NONE", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "1Gx9QwpQBFnAjF27Uiz3ea2zYBDrLx31bw",
            &coin,
        ));

        let coin = coin_info_from_param("BITCOIN", "MAINNET", "VERSION_0", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "bc1qnfv46v0wtarc6n82dnehtvzj2gtnqzjhj5wxqj",
            &coin,
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "NONE", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP",
            &coin,
        ));
        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(BtcKinAddress::is_valid(
            "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW",
            &coin,
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(!BtcKinAddress::is_valid(
            "MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDf",
            &coin,
        ));

        let coin = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
        assert!(!BtcKinAddress::is_valid("aaa", &coin));
    }

    #[test]
    fn cross_test_tw() {
        let prv_str = "28071bf4e2b0340db41b807ed8a5514139e5d6427ff9d58dbd22b7ed187103a4";
        let pub_key =
            TypedPrivateKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(prv_str).unwrap())
                .unwrap()
                .public_key();
        let mut coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/2'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        };
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "1PeUvjuxyf31aJKX6kCXuaqxhmG78ZUdL1");

        let pub_str = "030589ee559348bd6a7325994f9c8eff12bd5d73cc683142bd0dd1a17abc99b0dc";
        let pub_key =
            TypedPublicKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(pub_str).unwrap())
                .unwrap();
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "1KbUJ4x8epz6QqxkmZbTc4f79JbWWz6g37");

        let pub_str = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let pub_key =
            TypedPublicKey::from_slice(CurveType::SECP256k1, &Vec::from_hex(pub_str).unwrap())
                .unwrap();
        coin_info.seg_wit = "VERSION_0".to_string();
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_dogecoin_address() {
        let mut hd = sample_hd_keystore();
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "DQ4tVEqdPWHc1aVBm4Sfwft8XyNRPMEchR");
        assert_eq!(account.ext_pub_key, "xpub6CDSaXHQokkKmHHG2kNCFZeirJkcZgRZE97ZZUtViif3SFHSNVAvRpWC3CxeRt2VZetEGCcPTmWEFpKF4NDeeZrMNPQgfUaX5Hkw89kW8qE");
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/3'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "no7xDFaYKUkKtZ4Nnt68C5URmqkiMUTRTE");

        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "A6tT5rU6MZBzArAVVei5PqqocfxBqJhSqg");
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "2N7hQQkLDtwpSUGRZkefXmfCh8SnKabUcC5");

        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "1q8qlms89s5078yj67pr8ch02qgvmdwy0k24vwhn");
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "1q8qlms89s5078yj67pr8ch02qgvmdwy0k24vwhn");

        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
            })
            .unwrap();
        assert_eq!(
            account.address,
            "1pd2gajgcpr7c5ajgl377sgmqexw5jxqvl305zw2a7aeujf8pun7ksh45tuj"
        );
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
            })
            .unwrap();
        assert_eq!(
            account.address,
            "1pd2gajgcpr7c5ajgl377sgmqexw5jxqvl305zw2a7aeujf8pun7ksh45tuj"
        );
    }

    #[test]
    fn test_dogecoin_address2() {
        let mut hd = sample_hd_keystore();
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/0".to_string(),
                curve: CurveType::SECP256k1,
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "DAGWiHeAHCTLUTsBEFMWviSkdGeZGveASM");
        // assert_eq!(account.ext_pub_key, "xpub6CDSaXHQokkKmHHG2kNCFZeirJkcZgRZE97ZZUtViif3SFHSNVAvRpWC3CxeRt2VZetEGCcPTmWEFpKF4NDeeZrMNPQgfUaX5Hkw89kW8qE");
        let account = hd
            .derive_coin::<BtcKinAddress>(&CoinInfo {
                chain_id: "".to_string(),
                coin: "DOGECOIN".to_string(),
                derivation_path: "m/44'/1'/0'/0/22".to_string(),
                curve: CurveType::SECP256k1,
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            })
            .unwrap();
        assert_eq!(account.address, "nZKaSJP5DAv4MSSNG4zyB833s92rHdzyqW");
    }

    #[test]
    fn test_dogecoin_address_from_str() {
        let addr = BtcKinAddress::from_str("DQ4tVEqdPWHc1aVBm4Sfwft8XyNRPMEchR").unwrap();
        assert_eq!(addr.network.coin, "DOGECOIN");
        assert_eq!(addr.network.network, "MAINNET");
    }

    #[test]
    fn test_xpub() {
        let mut hd = sample_hd_keystore();

        let test_cases = [
            ("BITCOIN", "MAINNET", "m/44'/0'/0/0", "xpub6CqzLtyBHdq6tZD7Bdxo9bpCEWfFBg7dim6UMxs83nqNYzFatwkr9yGkLtG5ktiKcgaUqP5BpuTMJLyaLQ167gANU8ZsfLRN86VXyx3atJX"),
            ("LITECOIN", "MAINNET", "m/44'/2'/0'/0/0", "xpub6D3MqTwuLWB5veAfhDjPu1oHfS6L1imVbf22zQFWJW9EtnSmYYqiGMGkW1MCsT2HmkW872tefMY9deewW6DGd8zE7RcXVv8wKhZnbJeidjT"),
            ("DOGECOIN", "MAINNET", "m/44'/3'/0'/0/0", "xpub6CDSaXHQokkKmHHG2kNCFZeirJkcZgRZE97ZZUtViif3SFHSNVAvRpWC3CxeRt2VZetEGCcPTmWEFpKF4NDeeZrMNPQgfUaX5Hkw89kW8qE"),
        ];

        for (coin, network, path, xpub) in test_cases {
            let coin_info = CoinInfo {
                chain_id: "".to_string(),
                coin: coin.to_string(),
                derivation_path: path.to_string(),
                curve: CurveType::SECP256k1,
                network: network.to_string(),
                seg_wit: "NONE".to_string(),
            };
            let account = hd.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
            assert_eq!(account.ext_pub_key, xpub);
        }
    }

    #[test]
    fn test_bip84_spec_vector() {
        let pub_key = TypedPublicKey::from_slice(
            CurveType::SECP256k1,
            &Vec::from_hex("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")
                .unwrap(),
        )
        .unwrap();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: "BITCOIN".to_string(),
            derivation_path: "m/84'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "VERSION_0".to_string(),
        };
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        let pub_key = TypedPublicKey::from_slice(
            CurveType::SECP256k1,
            &Vec::from_hex("03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77")
                .unwrap(),
        )
        .unwrap();
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");

        let pub_key = TypedPublicKey::from_slice(
            CurveType::SECP256k1,
            &Vec::from_hex("03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6")
                .unwrap(),
        )
        .unwrap();
        let address = BtcKinAddress::from_public_key(&pub_key, &coin_info)
            .unwrap()
            .to_string();
        assert_eq!(address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }
}
