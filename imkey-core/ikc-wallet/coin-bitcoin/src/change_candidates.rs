use crate::input_proof::authenticated_transaction_chunk;
use crate::Result;
use anyhow::anyhow;
use bitcoin::psbt::Output;
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use bitcoin::{Address, Network, PublicKey, Script};
use ikc_common::apdu::ApduCheck;
use ikc_common::constants::TIMEOUT_LONG;
use ikc_common::error::CoinError;
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::Secp256k1;

const CHANGE_HINT_INS: u8 = 0x54;
pub(crate) const MAX_CHANGE_CANDIDATES: usize = 16;

pub(crate) fn bitcoin_network_id(network: Network) -> Result<u8> {
    match network {
        Network::Bitcoin => Ok(0),
        Network::Testnet => Ok(1),
        _ => Err(CoinError::ImkeySdkIllegalArgument.into()),
    }
}

pub(crate) fn canonical_change_path(
    path: &DerivationPath,
    script: &Script,
    network_id: u8,
    allow_receive_branch: bool,
) -> Option<String> {
    let purpose = if script.is_p2pkh() {
        44
    } else if script.is_p2sh() {
        49
    } else if script.is_v0_p2wpkh() {
        84
    } else if script.is_v1_p2tr() {
        86
    } else {
        return None;
    };
    use ChildNumber::{Hardened, Normal};
    match path.as_ref() {
        [Hardened {
            index: path_purpose,
        }, Hardened { index: coin }, Hardened { .. }, Normal { index: branch }, Normal { .. }]
            if *path_purpose == purpose
                && *coin == u32::from(network_id)
                && (*branch == 1 || (allow_receive_branch && *branch == 0)) =>
        {
            Some(path.to_string())
        }
        _ => None,
    }
}

pub(crate) fn psbt_change_path(
    output: &Output,
    script: &Script,
    network: Network,
    network_id: u8,
) -> Option<String> {
    if output.witness_script.is_some() || output.tap_tree.is_some() {
        return None;
    }

    let path = if script.is_v1_p2tr() {
        if output.redeem_script.is_some()
            || !output.bip32_derivation.is_empty()
            || output.tap_key_origins.len() != 1
        {
            return None;
        }
        let (key, (leaves, (_, path))) = output.tap_key_origins.first_key_value()?;
        if !leaves.is_empty()
            || output
                .tap_internal_key
                .map_or(false, |internal| internal != *key)
            || *script != Script::new_v1_p2tr(&Secp256k1::verification_only(), *key, None)
        {
            return None;
        }
        path
    } else {
        if !output.tap_key_origins.is_empty()
            || output.tap_internal_key.is_some()
            || output.bip32_derivation.len() != 1
        {
            return None;
        }
        let (key, (_, path)) = output.bip32_derivation.first_key_value()?;
        let public_key = PublicKey::new(*key);
        let expected = if script.is_p2sh() {
            let redeem = Address::p2wpkh(&public_key, network).ok()?.script_pubkey();
            if output
                .redeem_script
                .as_ref()
                .map_or(false, |script| *script != redeem)
            {
                return None;
            }
            Address::p2shwpkh(&public_key, network).ok()?
        } else {
            if output.redeem_script.is_some() {
                return None;
            }
            if script.is_p2pkh() {
                Address::p2pkh(&public_key, network)
            } else if script.is_v0_p2wpkh() {
                Address::p2wpkh(&public_key, network).ok()?
            } else {
                return None;
            }
        };
        if *script != expected.script_pubkey() {
            return None;
        }
        path
    };

    canonical_change_path(path, script, network_id, false)
}

/// A single account inferred from all of the verified funding scripts and device keys.
pub(crate) struct SingleWalletChange {
    input_paths: Vec<DerivationPath>,
}

impl SingleWalletChange {
    pub(crate) fn from_inputs<'a>(
        network: Network,
        inputs: impl IntoIterator<Item = (&'a str, &'a Script, &'a str)>,
    ) -> Option<Self> {
        let network_id = bitcoin_network_id(network).ok()?;
        let secp = Secp256k1::verification_only();
        let mut input_paths: Vec<DerivationPath> = Vec::new();
        for (path, script, public_key) in inputs {
            let path: DerivationPath = path.to_ascii_lowercase().parse().ok()?;
            canonical_change_path(&path, script, network_id, true)?;
            if input_paths
                .first()
                .map_or(false, |first| first.as_ref()[..3] != path.as_ref()[..3])
            {
                return None;
            }
            let public_key: secp256k1::PublicKey = public_key.parse().ok()?;
            let key = PublicKey::new(public_key);
            let expected = if script.is_p2pkh() {
                Address::p2pkh(&key, network).script_pubkey()
            } else if script.is_p2sh() {
                Address::p2shwpkh(&key, network).ok()?.script_pubkey()
            } else if script.is_v0_p2wpkh() {
                Address::p2wpkh(&key, network).ok()?.script_pubkey()
            } else {
                Script::new_v1_p2tr(&secp, public_key.x_only_public_key().0, None)
            };
            if expected != *script {
                return None;
            }
            input_paths.push(path);
        }
        (!input_paths.is_empty()).then_some(Self { input_paths })
    }

    pub(crate) fn allows(&self, candidate: &str) -> bool {
        let path = match candidate.parse::<DerivationPath>() {
            Ok(path) if path.as_ref().len() == 5 => path,
            _ => return false,
        };
        self.input_paths[0].as_ref()[..3] == path.as_ref()[..3]
            && (path.as_ref()[3] == ChildNumber::Normal { index: 1 } || self.input_paths[0] == path)
    }

    pub(crate) fn send(&self) -> Result<()> {
        let key_manager = KEY_MANAGER.lock();
        for (index, path) in self.input_paths.iter().enumerate() {
            let path = path.to_string();
            send_authenticated_change_command(
                0x56,
                index as u8,
                0,
                path.as_bytes(),
                &key_manager.pri_key,
                path.starts_with("m/86'/"),
            )?;
        }
        Ok(())
    }
}

pub(crate) fn send_change_candidates(
    network_id: u8,
    candidates: impl IntoIterator<Item = (usize, String)>,
    remaining: usize,
) -> Result<()> {
    let key_manager = KEY_MANAGER.lock();
    for (index, path) in candidates.into_iter().take(remaining) {
        if index >= 0xff {
            return Err(anyhow!("btc_change_candidate_output_index_out_of_range"));
        }
        let is_taproot = path.starts_with("m/86'/");
        let phase = if is_taproot { 2 } else { 0 };
        send_authenticated_change_command(
            CHANGE_HINT_INS,
            index as u8,
            phase,
            path.as_bytes(),
            &key_manager.pri_key,
            is_taproot,
        )?;
    }
    send_authenticated_change_command(
        CHANGE_HINT_INS,
        0xff,
        0x80,
        &[network_id],
        &key_manager.pri_key,
        false,
    )
}

pub(crate) fn send_authenticated_change_command(
    ins: u8,
    index: u8,
    phase: u8,
    fragment: &[u8],
    key: &[u8],
    long_timeout: bool,
) -> Result<()> {
    let apdu = authenticated_transaction_chunk(ins, index, phase, fragment, key)?;
    let response = if long_timeout {
        send_apdu_timeout(apdu, TIMEOUT_LONG)?
    } else {
        send_apdu(apdu)?
    };
    if response.len() != 4 || !response.is_ascii() {
        return Err(anyhow!("btc_change_candidate_invalid_response"));
    }
    ApduCheck::check_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{KeyPair, SecretKey, XOnlyPublicKey};

    #[test]
    fn psbt_change_requires_standard_paths_and_unambiguous_single_key_metadata() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1; 32]).unwrap().public_key(&secp);
        let other_key = SecretKey::from_slice(&[2; 32]).unwrap().public_key(&secp);
        let public = PublicKey::new(key);
        let network = Network::Bitcoin;
        let cases = [
            (Address::p2pkh(&public, network), "m/44'/0'/0'/1/23"),
            (
                Address::p2shwpkh(&public, network).unwrap(),
                "m/49'/0'/0'/1/23",
            ),
            (
                Address::p2wpkh(&public, network).unwrap(),
                "m/84'/0'/0'/1/23",
            ),
        ];
        for (address, path) in cases {
            let script = address.script_pubkey();
            let mut output = Output::default();
            output
                .bip32_derivation
                .insert(key, (Default::default(), path.parse().unwrap()));
            assert_eq!(
                psbt_change_path(&output, &script, network, 0).as_deref(),
                Some(path)
            );

            output
                .bip32_derivation
                .insert(other_key, (Default::default(), path.parse().unwrap()));
            assert!(psbt_change_path(&output, &script, network, 0).is_none());
            output.bip32_derivation.remove(&key);
            assert!(psbt_change_path(&output, &script, network, 0).is_none());
        }

        let script = Address::p2wpkh(&public, network).unwrap().script_pubkey();
        let receive_path = "m/84'/0'/0'/0/23".parse().unwrap();
        assert!(canonical_change_path(&receive_path, &script, 0, true).is_some());
        assert!(canonical_change_path(&receive_path, &script, 0, false).is_none());
        assert!(canonical_change_path(&receive_path, &script, 1, true).is_none());
    }

    #[test]
    fn only_a_matching_simple_taproot_key_origin_is_a_candidate() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let pair = KeyPair::from_secret_key(&secp, &secret);
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&pair);
        let network = Network::Testnet;
        let script = Script::new_v1_p2tr(&secp, internal_key, None);
        let mut output = Output::default();
        let path = "m/86'/1'/0'/1/7";
        output.tap_internal_key = Some(internal_key);
        output.tap_key_origins.insert(
            internal_key,
            (vec![], (Default::default(), path.parse().unwrap())),
        );
        assert_eq!(
            psbt_change_path(&output, &script, network, 1).as_deref(),
            Some(path)
        );

        output.witness_script = Some(Script::new());
        assert!(psbt_change_path(&output, &script, network, 1).is_none());
    }
}
