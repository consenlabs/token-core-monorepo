use crate::Result;
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use std::str::FromStr;

/// Validate a complete BIP44-family signing path, never an account or root key.
/// Coin and purpose allowlists belong to the calling chain's signing policy.
pub fn validate_bip44_signing_path(path: &str, coin_types: &[u32], purposes: &[u32]) -> Result<()> {
    if !path.starts_with("m/") {
        return Err(anyhow::anyhow!("invalid_sign_path"));
    }
    let path = DerivationPath::from_str(path).map_err(|_| anyhow::anyhow!("invalid_sign_path"))?;
    match path.as_ref() {
        [ChildNumber::Hardened { index: purpose }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { .. }, ChildNumber::Normal { index: change }, ChildNumber::Normal { .. }]
            if purposes.contains(purpose) && coin_types.contains(coin) && *change <= 1 =>
        {
            Ok(())
        }
        _ => Err(anyhow::anyhow!("invalid_sign_path")),
    }
}

pub fn validate_btc_signing_path(path: &str, chain: &str, network: &str) -> Result<()> {
    let coin = match chain {
        "BITCOIN" | "OMNI" => 0,
        "LITECOIN" => 2,
        "DOGECOIN" => 3,
        "BITCOINCASH" => 145,
        _ => return Err(anyhow::anyhow!("invalid_sign_path")),
    };
    let coins = match network {
        "MAINNET" => vec![coin],
        // Historical wallets also derive test-network addresses using the
        // chain's normal coin type. Preserve those accounts while rejecting
        // paths belonging to unrelated chains.
        "TESTNET" => vec![coin, 1],
        _ => return Err(anyhow::anyhow!("invalid_sign_path")),
    };
    validate_bip44_signing_path(path, &coins, &[44, 49, 84, 86])
}

pub fn validate_same_bip44_account(path: &str, account: &str) -> Result<()> {
    let path = DerivationPath::from_str(path).map_err(|_| anyhow::anyhow!("invalid_sign_path"))?;
    let account =
        DerivationPath::from_str(account).map_err(|_| anyhow::anyhow!("invalid_sign_path"))?;
    match (path.as_ref().get(1..3), account.as_ref().get(1..3)) {
        (Some(left), Some(right)) if left == right => Ok(()),
        _ => Err(anyhow::anyhow!("invalid_sign_path")),
    }
}

#[cfg(test)]
mod signing_path_tests {
    use super::*;
    #[test]
    fn signing_paths_reject_root_cross_chain_and_weak_structure() {
        assert!(validate_bip44_signing_path("m/44'/195'/0'/0/0", &[195], &[44]).is_ok());
        for path in [
            "",
            "m",
            "44'/195'/0'/0/0",
            "m/44'/195'/0'",
            "m/44'/60'/0'/0/0",
            "m/44/195'/0'/0/0",
            "m/44'/195'/0'/0'/0",
            "m/44'/195'/0'/2/0",
        ] {
            assert!(validate_bip44_signing_path(path, &[195], &[44]).is_err());
        }
        assert!(validate_btc_signing_path("m/44'/2'/0'/0/0", "LITECOIN", "TESTNET").is_ok());
        assert!(validate_same_bip44_account("m/44'/1'/1'/0/0", "m/84'/1'/0'/0/0").is_err());
    }
}
