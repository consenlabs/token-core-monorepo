use crate::{Result, BITCOIN, BITCOINCASH, DOGECOIN, LITECOIN, OMNI};
use anyhow::{anyhow, ensure};
use bitcoin::schnorr::TapTweak;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::{PubkeyHash, Script, WPubkeyHash};
use std::str::FromStr;
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, SECP256K1_ENGINE};

pub(crate) fn validate_path(path: &str, chain: &str, network: Option<&str>) -> Result<()> {
    let main_coin = match chain {
        BITCOIN | OMNI => 0,
        BITCOINCASH => 145,
        LITECOIN => 2,
        DOGECOIN => 3,
        _ => return Err(anyhow!("unsupported_chain")),
    };
    let coin_types = match network {
        Some("MAINNET") => vec![main_coin],
        Some("TESTNET") => vec![main_coin, 1],
        None => vec![main_coin, 1],
        _ => return Err(anyhow!("missing_network")),
    };
    tcx_primitive::signing_path::validate_bip44_signing_path(path, &coin_types, &[44, 49, 84, 86])
        .map_err(|_| anyhow!("invalid_sign_path"))
}

/// Mixed script types (44/49/84/86) remain supported within the same account.
pub(crate) fn same_account(path: &str, account: &str) -> Result<()> {
    let path = DerivationPath::from_str(path)?;
    let account = DerivationPath::from_str(account)?;
    ensure!(
        path.as_ref().get(1..3) == account.as_ref().get(1..3),
        "invalid_sign_path"
    );
    Ok(())
}

pub(crate) fn validate_key(script: &bitcoin::Script, key: &Secp256k1PrivateKey) -> Result<()> {
    let public_key = key.public_key();
    let compressed = public_key.to_compressed();
    let compressed_hash = bitcoin_hashes::hash160::Hash::hash(&compressed);
    use bitcoin_hashes::Hash;
    let matches = if script.is_p2pkh() {
        *script == Script::new_p2pkh(&PubkeyHash::from_hash(compressed_hash))
            || *script
                == Script::new_p2pkh(&PubkeyHash::from_hash(bitcoin_hashes::hash160::Hash::hash(
                    &public_key.to_uncompressed(),
                )))
    } else if script.is_v0_p2wpkh() {
        *script == Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(compressed_hash))
    } else if script.is_p2sh() {
        let redeem = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(compressed_hash));
        *script == redeem.to_p2sh()
    } else if script.is_v1_p2tr() {
        let (internal_key, _) = public_key.0.inner.x_only_public_key();
        let (output_key, _) = internal_key.tap_tweak(&SECP256K1_ENGINE, None);
        *script == Script::new_v1_p2tr_tweaked(output_key)
    } else {
        false
    };
    ensure!(matches, "invalid_utxo");
    Ok(())
}
