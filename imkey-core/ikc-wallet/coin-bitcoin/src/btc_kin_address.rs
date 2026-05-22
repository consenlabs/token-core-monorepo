use crate::common::get_xpub_data;
use crate::network::BtcKinNetwork;
use crate::Result;
use bitcoin::base58;
use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1};
use bitcoin::Network;
use bitcoin::{Address as LibAddress, PublicKey, ScriptBuf as Script};
use bitcoin::{CompressedPublicKey, PubkeyHash, ScriptHash, WitnessVersion};
use core::result;
use ikc_common::apdu::{ApduCheck, BtcApdu, CoinCommonApdu};
use ikc_common::coin_info::CoinInfo;
use ikc_common::constants;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::path::get_parent_path;
use ikc_common::utility::hex_to_bytes;
use ikc_transport::message::send_apdu;
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub trait AddressTrait {
    fn from_public_key(
        public_key: &str,
        network: &BtcKinNetwork,
        seg_wit: &str,
    ) -> Result<BtcKinAddress>;

    fn is_valid(address: &str, coin: &CoinInfo) -> bool;
}

pub trait ScriptPubkey {
    fn script_pubkey(&self) -> Script;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtcKinAddress {
    pub network: BtcKinNetwork,
    pub payload: BtcKinPayload,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BtcKinPayload {
    PubkeyHash(PubkeyHash),
    ScriptHash(ScriptHash),
    WitnessProgram {
        version: WitnessVersion,
        program: Vec<u8>,
    },
}

impl AddressTrait for BtcKinAddress {
    fn from_public_key(
        public_key: &str,
        network: &BtcKinNetwork,
        seg_wit: &str,
    ) -> Result<BtcKinAddress> {
        let mut pub_key_obj = PublicKey::from_str(public_key)?;
        pub_key_obj.compressed = true;

        let address = match seg_wit {
            constants::BTC_SEG_WIT_TYPE_P2WPKH => {
                let compressed = CompressedPublicKey::try_from(pub_key_obj)?;
                BtcKinAddress::from_lib_address(
                    LibAddress::p2shwpkh(&compressed, Network::Bitcoin),
                    network,
                )?
            }
            constants::BTC_SEG_WIT_TYPE_VERSION_0 => {
                let compressed = CompressedPublicKey::try_from(pub_key_obj)?;
                BtcKinAddress::from_lib_address(
                    LibAddress::p2wpkh(&compressed, Network::Bitcoin),
                    network,
                )?
            }
            constants::BTC_SEG_WIT_TYPE_VERSION_1 => {
                let public_key =
                    bitcoin::secp256k1::PublicKey::from_slice(&hex_to_bytes(&public_key)?)?;
                let (x_only, _) = public_key.x_only_public_key();
                let untweak_pub_key = UntweakedPublicKey::from(x_only);
                let secp = Secp256k1::new();
                let output_key = untweak_pub_key.tap_tweak(&secp, None).0;
                BtcKinAddress {
                    payload: BtcKinPayload::WitnessProgram {
                        version: WitnessVersion::V1,
                        program: output_key.serialize().to_vec(),
                    },
                    network: network.clone(),
                }
            }
            _ => BtcKinAddress::from_lib_address(
                LibAddress::p2pkh(&pub_key_obj, Network::Bitcoin),
                network,
            )?,
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
    pub fn p2pkh(network: &BtcKinNetwork, path: &str) -> Result<BtcKinAddress> {
        check_path_validity(path)?;

        let pub_key = &get_xpub_data(path, true)?[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;

        BtcKinAddress::from_lib_address(LibAddress::p2pkh(&pub_key_obj, Network::Bitcoin), network)
    }

    pub fn p2shwpkh(network: &BtcKinNetwork, path: &str) -> Result<BtcKinAddress> {
        check_path_validity(path)?;

        let pub_key = &get_xpub_data(path, true)?[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;

        let compressed = CompressedPublicKey::try_from(pub_key_obj)?;
        BtcKinAddress::from_lib_address(
            LibAddress::p2shwpkh(&compressed, Network::Bitcoin),
            network,
        )
    }

    pub fn p2wpkh(network: &BtcKinNetwork, path: &str) -> Result<BtcKinAddress> {
        check_path_validity(path)?;

        let pub_key = &get_xpub_data(path, true)?[..130];

        let mut pub_key_obj = PublicKey::from_str(pub_key)?;
        pub_key_obj.compressed = true;
        let compressed = CompressedPublicKey::try_from(pub_key_obj)?;
        BtcKinAddress::from_lib_address(LibAddress::p2wpkh(&compressed, Network::Bitcoin), network)
    }

    pub fn p2tr(network: &BtcKinNetwork, path: &str) -> Result<BtcKinAddress> {
        check_path_validity(path)?;

        let pub_key = &get_xpub_data(path, true)?[..130];
        let public_key = bitcoin::secp256k1::PublicKey::from_slice(&hex_to_bytes(&pub_key)?)?;
        let (x_only, _) = public_key.x_only_public_key();
        let untweak_pub_key = UntweakedPublicKey::from(x_only);
        let secp = Secp256k1::new();
        let output_key = untweak_pub_key.tap_tweak(&secp, None).0;
        Ok(BtcKinAddress {
            payload: BtcKinPayload::WitnessProgram {
                version: WitnessVersion::V1,
                program: output_key.serialize().to_vec(),
            },
            network: network.clone(),
        })
    }

    pub fn display_address(network: &BtcKinNetwork, path: &str, seg_wit: &str) -> Result<String> {
        check_path_validity(path)?;

        let address = match seg_wit {
            constants::BTC_SEG_WIT_TYPE_P2WPKH => Self::p2shwpkh(network, path)?,
            constants::BTC_SEG_WIT_TYPE_VERSION_0 => Self::p2wpkh(network, path)?,
            constants::BTC_SEG_WIT_TYPE_VERSION_1 => Self::p2tr(network, path)?,
            _ => Self::p2pkh(network, path)?,
        };

        let apdu_res = send_apdu(BtcApdu::register_address(&address.to_string().as_bytes()))?;
        ApduCheck::check_response(apdu_res.as_str())?;
        Ok(address.to_string())
    }

    pub fn script_pubkey(&self) -> Script {
        match &self.payload {
            BtcKinPayload::PubkeyHash(hash) => Script::new_p2pkh(hash),
            BtcKinPayload::ScriptHash(hash) => Script::new_p2sh(hash),
            BtcKinPayload::WitnessProgram { version, program } => {
                let witness_program =
                    bitcoin::WitnessProgram::new(*version, program).expect("valid witness program");
                Script::new_witness_program(&witness_program)
            }
        }
    }

    fn from_lib_address(address: LibAddress, network: &BtcKinNetwork) -> Result<BtcKinAddress> {
        let script = address.script_pubkey();
        let payload = if script.is_p2pkh() {
            BtcKinPayload::PubkeyHash(address.pubkey_hash().ok_or(CoinError::InvalidAddress)?)
        } else if script.is_p2sh() {
            BtcKinPayload::ScriptHash(address.script_hash().ok_or(CoinError::InvalidAddress)?)
        } else if script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr() {
            let witness_program = address.witness_program().ok_or(CoinError::InvalidAddress)?;
            BtcKinPayload::WitnessProgram {
                version: witness_program.version(),
                program: witness_program.program().as_bytes().to_vec(),
            }
        } else {
            return Err(CoinError::InvalidAddress.into());
        };
        Ok(BtcKinAddress {
            payload,
            network: network.clone(),
        })
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
            let (_, version, program) = bech32::segwit::decode(s)?;
            if program.is_empty() {
                return Err(CoinError::InvalidAddress.into());
            }
            return Ok(BtcKinAddress {
                payload: BtcKinPayload::WitnessProgram {
                    version: WitnessVersion::try_from(version.to_u8())?,
                    program,
                },
                network: network.clone(),
            });
        }

        let data = decode_base58(s).map_err(|_| CoinError::InvalidAddress)?;
        if let Some(network) = BtcKinNetwork::find_by_prefix(data[0]) {
            if network.p2pkh_prefix == data[0] {
                return Ok(BtcKinAddress {
                    network: network.clone(),
                    payload: BtcKinPayload::PubkeyHash(PubkeyHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                });
            } else if network.p2sh_prefix == data[0] {
                return Ok(BtcKinAddress {
                    network: network.clone(),
                    payload: BtcKinPayload::ScriptHash(ScriptHash::from_byte_array(
                        data[1..].try_into().unwrap(),
                    )),
                });
            }
        }

        Err(CoinError::InvalidAddress.into())
    }
}

impl Display for BtcKinAddress {
    fn fmt(&self, fmt: &mut Formatter) -> core::fmt::Result {
        match self.payload {
            BtcKinPayload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            BtcKinPayload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.network.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            BtcKinPayload::WitnessProgram {
                version,
                program: ref prog,
            } => {
                let hrp =
                    bech32::Hrp::parse(self.network.bech32_hrp).map_err(|_| core::fmt::Error)?;
                bech32::segwit::encode_to_fmt_unchecked(fmt, hrp, version.to_fe(), prog)
            }
        }
    }
}

fn bech32_network(bech32: &str) -> Option<&BtcKinNetwork> {
    let bech32_prefix = bech32.rfind('1').map(|sep| bech32.split_at(sep).0);

    if bech32_prefix.is_some() {
        let prefix = bech32_prefix.unwrap();
        if !prefix.is_empty() {
            return BtcKinNetwork::find_by_hrp(prefix);
        }
    }
    return None;
}

fn decode_base58(addr: &str) -> result::Result<Vec<u8>, CoinError> {
    // Base58
    if addr.len() > 50 {
        return Err(CoinError::InvalidAddress);
    }
    let data = base58::decode_check(addr).map_err(|_| CoinError::InvalidAddress)?;
    if data.len() != 21 {
        Err(CoinError::InvalidAddress)
    } else {
        Ok(data)
    }
}

pub struct ImkeyPublicKey();

impl ImkeyPublicKey {
    pub fn get_xpub(network: Network, path: &str) -> Result<String> {
        check_path_validity(path)?;

        let xpub_data = get_xpub_data(path, true)?;
        let xpub_data = &xpub_data[..194].to_string();

        let pub_key = &xpub_data[..130];
        let chain_code = &xpub_data[130..];

        let parent_xpub = get_xpub_data(get_parent_path(path)?, true)?;
        let parent_xpub = &parent_xpub[..130].to_string();
        let parent_pub_key_obj = Secp256k1PublicKey::from_str(parent_xpub)?;

        let pub_key_obj = Secp256k1PublicKey::from_str(pub_key)?;

        let chain_code_obj = ChainCode::try_from(hex::decode(chain_code)?.as_slice())?;
        let parent_ext_pub_key = Xpub {
            network: network.into(),
            depth: 0u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: parent_pub_key_obj,
            chain_code: chain_code_obj,
        };
        let fingerprint_obj = parent_ext_pub_key.fingerprint();

        //build extend public key obj
        let chain_code_obj = ChainCode::try_from(hex::decode(chain_code)?.as_slice())?;
        let chain_number_vec: Vec<ChildNumber> = DerivationPath::from_str(path)?.into();
        let extend_public_key = Xpub {
            network: network.into(),
            depth: chain_number_vec.len() as u8,
            parent_fingerprint: fingerprint_obj,
            child_number: *chain_number_vec.get(chain_number_vec.len() - 1).unwrap(),
            public_key: pub_key_obj,
            chain_code: chain_code_obj,
        };
        Ok(extend_public_key.to_string())
    }

    pub fn get_pub_key(path: &str) -> Result<String> {
        check_path_validity(path)?;

        let xpub_data = get_xpub_data(path, true)?;
        let pub_key = &xpub_data[..130];

        Ok(pub_key.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        btc_kin_address::{BtcKinAddress, ImkeyPublicKey},
        network::BtcKinNetwork,
    };
    use bitcoin::Network;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn get_xpub_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'/0'/0'/0/0";
        let get_xpub_result = ImkeyPublicKey::get_xpub(version, path);
        assert!(get_xpub_result.is_ok());
        let xpub = get_xpub_result.ok().unwrap();
        assert_eq!("xpub6FuzpGNBc46EfvmcvECyqXjrzGcKErQgpQcpvhw1tiC5yXvi1jUkzudMpdg5AaguiFstdVR5ASDbSceBswKRy6cAhpTgozmgxMUayPDrLLX", xpub);
    }

    #[test]
    fn get_xpub_path_error_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "m/44'";
        let get_xpub_result = ImkeyPublicKey::get_xpub(version, path);
        assert!(get_xpub_result.is_err());
    }

    #[test]
    fn get_xpub_path_is_null_test() {
        bind_test();

        let version: Network = Network::Bitcoin;
        let path: &str = "";
        let get_xpub_result = ImkeyPublicKey::get_xpub(version, path);
        assert!(get_xpub_result.is_err());
    }

    #[test]
    fn p2pkh_test() {
        bind_test();

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/44'/0'/0'/0/0";
        let btc_address = BtcKinAddress::p2pkh(network, path).unwrap().to_string();

        assert_eq!("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g", btc_address);
    }

    #[test]
    fn p2shwpkh_address_test() {
        bind_test();

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/49'/0'/0'/0/22";
        let segwit_address = BtcKinAddress::p2shwpkh(network, path).unwrap().to_string();

        assert_eq!("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e", segwit_address);
    }
    #[test]
    fn p2wpkh_address_test() {
        bind_test();

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/49'/0'/0'/0/22";
        let address = BtcKinAddress::p2wpkh(network, path).unwrap().to_string();

        assert_eq!("bc1qe74h3vkdcj94uph4wdpk48nlqjdy42y87mdm7q", address);
    }

    #[test]
    fn p2tr_address_test() {
        bind_test();

        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/49'/0'/0'/0/22";
        let address = BtcKinAddress::p2tr(network, path).unwrap().to_string();

        assert_eq!(
            "bc1ph40wj9vl3kwhxq747wxkcr63e4r3uaryagpetnkey4zqhucmjfzse24jrd",
            address
        );
    }

    #[test]
    fn display_address_test() {
        bind_test();
        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/44'/0'/0'/0/0";
        let address = BtcKinAddress::display_address(network, path, "NONE").unwrap();

        assert_eq!("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g", address);
    }

    #[test]
    fn display_segwit_address_test() {
        bind_test();
        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/49'/0'/0'/0/22";
        let address = BtcKinAddress::display_address(network, path, "P2WPKH").unwrap();

        assert_eq!("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e", address);
    }

    #[test]
    fn display_native_segwit_address_test() {
        bind_test();
        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/84'/0'/0'";
        let address = BtcKinAddress::display_address(network, path, "VERSION_0").unwrap();

        assert_eq!("bc1qhuwav68m49d8epty9ztg8yag7ku27jfccyz3hp", address);
    }

    #[test]
    fn display_taproot_address_test() {
        bind_test();
        let network = BtcKinNetwork::find_by_coin("BITCOIN", "MAINNET").unwrap();
        let path: &str = "m/86'/0'/0'";
        let address = BtcKinAddress::display_address(network, path, "VERSION_1").unwrap();

        assert_eq!(
            "bc1p26r56upnktz0qm4vxw3228v956rxsc4sevasswxdvh9ysnq509fqctph3w",
            address
        );
    }

    #[test]
    fn test_dogecoin_address() {
        bind_test();

        let network = BtcKinNetwork::find_by_coin("DOGECOIN", "MAINNET").unwrap();
        let path: &str = "m/44'/3'/0'/0/0";
        let address = BtcKinAddress::p2pkh(network, path).unwrap().to_string();
        assert_eq!("DQ4tVEqdPWHc1aVBm4Sfwft8XyNRPMEchR", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2shwpkh(network, path).unwrap().to_string();
        assert_eq!("A6tT5rU6MZBzArAVVei5PqqocfxBqJhSqg", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2wpkh(network, path).unwrap().to_string();
        assert_eq!("1q8qlms89s5078yj67pr8ch02qgvmdwy0k24vwhn", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2tr(network, path).unwrap().to_string();
        assert_eq!(
            "1pd2gajgcpr7c5ajgl377sgmqexw5jxqvl305zw2a7aeujf8pun7ksh45tuj",
            address
        );

        let network = BtcKinNetwork::find_by_coin("DOGECOIN", "TESTNET").unwrap();
        let path: &str = "m/44'/3'/0'/0/0";
        let address = BtcKinAddress::p2pkh(network, path).unwrap().to_string();
        assert_eq!("no7xDFaYKUkKtZ4Nnt68C5URmqkiMUTRTE", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2shwpkh(network, path).unwrap().to_string();
        assert_eq!("2N7hQQkLDtwpSUGRZkefXmfCh8SnKabUcC5", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2wpkh(network, path).unwrap().to_string();
        assert_eq!("1q8qlms89s5078yj67pr8ch02qgvmdwy0k24vwhn", address);

        let path: &str = "m/44'/1'/0'/0/0";
        let address = BtcKinAddress::p2tr(network, path).unwrap().to_string();
        assert_eq!(
            "1pd2gajgcpr7c5ajgl377sgmqexw5jxqvl305zw2a7aeujf8pun7ksh45tuj",
            address
        );
    }
}
