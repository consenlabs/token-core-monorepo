use crate::btc_fork_network::{network_form_hrp, network_from_coin, BtcForkNetwork};
use crate::common::get_xpub_data;
use crate::Result;
use bitcoin::base58;
use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey as Secp256k1PublicKey;
use bitcoin::{Network, PubkeyHash, PublicKey, ScriptBuf as Script, ScriptHash, WitnessVersion};
use std::convert::{TryFrom, TryInto};

use ikc_common::coin_info::coin_info_from_param;
use ikc_common::coin_info::CoinInfo;
use ikc_common::error::{CoinError, CommonError};
use ikc_common::path::check_path_validity;

use ikc_common::utility::uncompress_pubkey_2_compress;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtcForkAddress {
    pub network: BtcForkNetwork,
    pub payload: BtcForkPayload,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BtcForkPayload {
    PubkeyHash(PubkeyHash),
    ScriptHash(ScriptHash),
    WitnessProgram {
        version: WitnessVersion,
        program: Vec<u8>,
    },
}

impl BtcForkAddress {
    pub fn get_enc_xpub(network: Network, path: &str) -> Result<String> {
        let xpub = Self::get_xpub(network, path)?;
        let key = ikc_common::XPUB_COMMON_KEY_128.read();
        let iv = ikc_common::XPUB_COMMON_IV.read();
        let key_bytes = hex::decode(&*key)?;
        let iv_bytes = hex::decode(&*iv)?;
        let encrypted =
            ikc_common::aes::cbc::encrypt_pkcs7(&xpub.as_bytes(), &key_bytes, &iv_bytes)?;
        Ok(base64::encode(&encrypted))
    }

    /**
    get xpub with path
    */
    pub fn get_xpub(network: Network, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub data
        let xpub_data = get_xpub_data(path, true)?;
        let xpub_data = &xpub_data[..194];
        let pub_key = &xpub_data[..130];
        let chain_code = &xpub_data[130..];

        //build parent xpub data
        let parent_xpub = get_xpub_data(Self::get_parent_path(path)?, true)?;
        let parent_xpub = &parent_xpub[..194];
        let parent_pub_key = &parent_xpub[..130];
        let parent_chain_code = &parent_xpub[130..];

        //build parent public key obj
        let parent_pub_key_obj = Secp256k1PublicKey::from_str(parent_pub_key)?;
        //build child public key obj
        let pub_key_obj = Secp256k1PublicKey::from_str(pub_key)?;

        //get parent public key fingerprint
        let chain_code_obj = ChainCode::try_from(hex::decode(parent_chain_code)?.as_slice())?;
        let parent_ext_pub_key = ExtendedPubKey {
            network: network.into(),
            depth: 0 as u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: parent_pub_key_obj,
            chain_code: chain_code_obj,
        };
        let fingerprint_obj = parent_ext_pub_key.fingerprint();

        //build extend public key obj
        let chain_code_obj = ChainCode::try_from(hex::decode(chain_code)?.as_slice())?;
        let chain_number_vec: Vec<ChildNumber> = DerivationPath::from_str(path)?.into();
        let extend_public_key = ExtendedPubKey {
            network: network.into(),
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: pub_key_obj,
            chain_code: chain_code_obj,
        };
        //get and return xpub
        Ok(extend_public_key.to_string())
    }

    /**
    get parent public key path
    */
    fn get_parent_path(path: &str) -> Result<&str> {
        if path.is_empty() {
            return Err(CommonError::ImkeyPathIllegal.into());
        }

        let mut end_flg = path.rfind("/").unwrap();
        if path.ends_with("/") {
            let path = &path[..path.len() - 1];
            end_flg = path.rfind("/").unwrap();
        }
        Ok(&path[..end_flg])
    }

    pub fn p2pkh(network: &BtcForkNetwork, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;
        let btc_fork_address = BtcForkAddress {
            payload: BtcForkPayload::PubkeyHash(pub_key_obj.pubkey_hash()),
            network: network.clone(),
        };

        Ok(btc_fork_address.to_string())
    }

    pub fn p2shwpkh(network: &BtcForkNetwork, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;
        let script = Script::new_p2wpkh(&pub_key_obj.wpubkey_hash()?);
        let btc_fork_address = BtcForkAddress {
            payload: BtcForkPayload::ScriptHash(script.script_hash()),
            network: network.clone(),
        };

        Ok(btc_fork_address.to_string())
    }

    pub fn p2wpkh(network: &BtcForkNetwork, path: &str) -> Result<String> {
        //path check
        check_path_validity(path)?;

        //get xpub
        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;
        let btc_fork_address = BtcForkAddress {
            payload: BtcForkPayload::WitnessProgram {
                version: WitnessVersion::V0,
                program: pub_key_obj.wpubkey_hash()?[..].to_vec(),
            },
            network: network.clone(),
        };

        Ok(btc_fork_address.to_string())
    }

    pub fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let ret = BtcForkAddress::from_str(address);
        if ret.is_err() {
            false
        } else {
            let addr: BtcForkAddress = ret.unwrap();
            addr.network.network == coin.network
        }
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = uncompress_pubkey_2_compress(&xpub_data[..130]);

        if pub_key.starts_with("0x") {
            Ok(pub_key)
        } else {
            Ok(format!("0x{}", pub_key))
        }
    }

    pub fn from_pub_key(pub_key: Vec<u8>, btc_fork_network: BtcForkNetwork) -> Result<String> {
        let mut public_key = PublicKey::from_slice(&pub_key)?;
        public_key.compressed = true;
        let address = match btc_fork_network.seg_wit.to_uppercase().as_str() {
            "P2WPKH" => {
                let script = Script::new_p2wpkh(&public_key.wpubkey_hash()?);
                BtcForkAddress {
                    payload: BtcForkPayload::ScriptHash(script.script_hash()),
                    network: btc_fork_network,
                }
            }
            _ => BtcForkAddress {
                payload: BtcForkPayload::PubkeyHash(public_key.pubkey_hash()),
                network: btc_fork_network,
            },
        };
        Ok(address.to_string())
    }
    pub fn script_pubkey(&self) -> Script {
        match &self.payload {
            BtcForkPayload::PubkeyHash(hash) => Script::new_p2pkh(hash),
            BtcForkPayload::ScriptHash(hash) => Script::new_p2sh(hash),
            BtcForkPayload::WitnessProgram { version, program } => {
                let witness_program =
                    bitcoin::WitnessProgram::new(*version, program).expect("valid witness program");
                Script::new_witness_program(&witness_program)
            }
        }
    }
}

impl FromStr for BtcForkAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<BtcForkAddress> {
        // try bech32
        let bech32_network = bech32_network(s);
        if let Some(network) = bech32_network {
            // decode as bech32
            let (_, version, program) = bech32::segwit::decode(s)?;
            if program.is_empty() {
                return Err(CoinError::EmptyBech32Payload.into());
            }
            let payload = BtcForkPayload::WitnessProgram {
                version: WitnessVersion::try_from(version.to_u8())?,
                program,
            };
            return Ok(BtcForkAddress { payload, network });
        }

        let data = decode_base58(s)?;
        let (network, payload) = match data[0] {
            0 => {
                let coin_info = coin_info_from_param("BITCOIN", "MAINNET", "NONE", "")
                    .expect("BtcForkNetwork coin_info");
                (
                    network_from_coin(&coin_info).expect("btc"),
                    BtcForkPayload::PubkeyHash(PubkeyHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            5 => {
                let coin_info = coin_info_from_param("BITCOIN", "MAINNET", "P2WPKH", "")
                    .expect("BITCOIN-P2WPKH coin_info");
                (
                    network_from_coin(&coin_info).expect("btc"),
                    BtcForkPayload::ScriptHash(ScriptHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            0x30 => {
                let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "NONE", "")
                    .expect("LITECOIN coin_info");
                (
                    network_from_coin(&coin_info).expect("ltc-L"),
                    BtcForkPayload::PubkeyHash(PubkeyHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            0x32 => {
                let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "")
                    .expect("LITECOIN-P2WPKH coin_info");
                (
                    network_from_coin(&coin_info).expect("ltc"),
                    BtcForkPayload::ScriptHash(ScriptHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            0x3a => {
                let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "P2WPKH", "")
                    .expect("LITECOIN TESTNET P2WPKH coin_info");
                (
                    network_from_coin(&coin_info).expect("ltc-testnet"),
                    BtcForkPayload::ScriptHash(ScriptHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            111 => {
                let coin_info = coin_info_from_param("BITCOIN", "TESTNET", "NONE", "")
                    .expect("BITCOIN-TESTNET coin_info");
                (
                    network_from_coin(&coin_info).expect("btc-testnet"),
                    BtcForkPayload::PubkeyHash(PubkeyHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            196 => {
                let coin_info = coin_info_from_param("BITCOIN", "TESTNET", "P2WPKH", "")
                    .expect("BITCOIN-TESTNET-P2WPKH coin_info");
                (
                    network_from_coin(&coin_info).expect("btc-testnet"),
                    BtcForkPayload::ScriptHash(ScriptHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                )
            }
            _ => {
                return Err(CoinError::InvalidVersion.into());
            }
        };

        Ok(BtcForkAddress { network, payload })
    }
}

impl Display for BtcForkAddress {
    fn fmt(&self, fmt: &mut Formatter) -> core::fmt::Result {
        match self.payload {
            BtcForkPayload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            BtcForkPayload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            BtcForkPayload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => {
                let hrp = bech32::Hrp::parse(self.network.hrp).map_err(|_| core::fmt::Error)?;
                bech32::segwit::encode_to_fmt_unchecked(fmt, hrp, ver.to_fe(), prog)
            }
        }
    }
}

/// Extract the bech32 prefix.
fn bech32_network(bech32: &str) -> Option<BtcForkNetwork> {
    let bech32_prefix = match bech32.rfind('1') {
        None => None,
        Some(sep) => Some(bech32.split_at(sep).0),
    };
    match bech32_prefix {
        Some(prefix) => network_form_hrp(prefix),
        None => None,
    }
}

fn decode_base58(addr: &str) -> Result<Vec<u8>> {
    // Base58
    if addr.len() > 50 {
        return Err(CoinError::InvalidAddrLength.into());
    }
    let data = base58::decode_check(&addr)?;
    if data.len() != 21 {
        return Err(CoinError::InvalidAddrLength.into());
    } else {
        Ok(data)
    }
}

#[cfg(test)]
mod test {
    use crate::address::BtcForkAddress;
    use crate::btc_fork_network::network_from_param;
    use bitcoin::Network;
    use ikc_device::device_binding::bind_test;
    use std::str::FromStr;

    #[test]
    fn get_xpub_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/0'/0'/0/0";
        let get_xpub_result = BtcForkAddress::get_xpub(version, path);
        assert!(get_xpub_result.is_ok());
        let xpub = get_xpub_result.ok().unwrap();
        assert_eq!("xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX", xpub);

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/2'/0'/0/0";
        let get_xpub_result = BtcForkAddress::get_xpub(version, path);
        assert!(get_xpub_result.is_ok());
        let xpub = get_xpub_result.ok().unwrap();
        assert_eq!("xpub6Gxe3rj6UCkx1oZSg36MnEtVcj6utTcuY2tHeyEgpXEnm9Hde8AVQrUHPnYS5mhRp4ML7GgeMCVgdpWE3gfN5hG4ayRUrF4e5UPuKEwzpns", xpub);

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/2'/0'/0/0";
        let get_enc_xpub_result = BtcForkAddress::get_enc_xpub(version, path);
        let enc_xpub = get_enc_xpub_result.ok().unwrap();
        assert_eq!("qO1zELT4UFoF3jVJ5qeo34HDSZVfDjd7u89H12wqyEQ4K1KEYoNVnBm61RyJevqOhwNKPJGrLp0QkJfJR3eFDKcI9rfvDl6bUXDZ+Kw1e4OzPSOkG8rwhqQnZKb7xd+xJSRRNkhLOMTEu0XutOqvjA==", enc_xpub);
    }

    #[test]
    fn test_btc_fork_address() {
        bind_test();
        let network = network_from_param("LITECOIN", "MAINNET", "NONE").unwrap();
        let path: &str = "m/44'/2'/0'/0/0";
        let get_address_result = BtcForkAddress::p2pkh(&network, path);

        assert!(get_address_result.is_ok());
        let addr = get_address_result.ok().unwrap();
        assert_eq!("Ldfdegx3hJygDuFDUA7Rkzjjx8gfFhP9DP", addr);

        let network = network_from_param("LITECOIN", "TESTNET", "NONE").unwrap();
        let path: &str = "m/44'/2'/0'/0/0";
        let get_address_result = BtcForkAddress::p2pkh(&network, path);

        assert!(get_address_result.is_ok());
        let addr = get_address_result.ok().unwrap();
        assert_eq!("myxdgXjCRgAskD2g1b6WJttJbuv67hq6sQ", addr);

        let network = network_from_param("LITECOIN", "MAINNET", "P2WPKH").unwrap();
        let path: &str = "m/44'/2'/0'/0/0";
        let get_address_result = BtcForkAddress::p2shwpkh(&network, path);

        assert!(get_address_result.is_ok());
        let addr = get_address_result.ok().unwrap();
        assert_eq!("M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd", addr);

        let network = network_from_param("LITECOIN", "MAINNET", "SEGWIT").unwrap();
        let path: &str = "m/44'/2'/0'/0/0";
        let get_address_result = BtcForkAddress::p2wpkh(&network, path);

        assert!(get_address_result.is_ok());
        let addr = get_address_result.ok().unwrap();
        assert_eq!("ltc1qefxc4n0dd88y7pwsjfv5d5nplpkxwh7cl75fny", addr);
    }

    #[test]
    pub fn test_btc_fork_address_from_str() {
        let addr = BtcForkAddress::from_str("MR5Hu9zXPX3o9QuYNJGft1VMpRP418QDfW").unwrap();
        assert_eq!(addr.network.coin, "LITECOIN");
        assert_eq!(addr.network.seg_wit, "P2WPKH");
        assert_eq!(addr.network.network, "MAINNET");
        let addr = BtcForkAddress::from_str("ltc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdn08yddf").unwrap();
        assert_eq!(addr.network.coin, "LITECOIN");
        assert_eq!(addr.network.seg_wit, "SEGWIT");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcForkAddress::from_str("3Js9bGaZSQCNLudeGRHL4NExVinc25RbuG").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.seg_wit, "P2WPKH");
        assert_eq!(addr.network.network, "MAINNET");
        let addr = BtcForkAddress::from_str("bc1qum864wd9nwsc0u9ytkctz6wzrw6g7zdntm7f4e").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.seg_wit, "SEGWIT");
        assert_eq!(addr.network.network, "MAINNET");
        let addr = BtcForkAddress::from_str("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.seg_wit, "NONE");
        assert_eq!(addr.network.network, "MAINNET");

        let addr = BtcForkAddress::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB").unwrap();
        assert_eq!(addr.network.coin, "BITCOIN");
        assert_eq!(addr.network.seg_wit, "P2WPKH");
        assert_eq!(addr.network.network, "TESTNET");
    }
}
