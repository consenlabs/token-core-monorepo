use crate::error::CommonError;
use crate::Result;
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use std::str::FromStr;

pub fn check_path_validity(path: &str) -> Result<()> {
    let path = path.trim_end_matches('/');
    let depth = path.split('/').count();
    if !(3..=6).contains(&depth) {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    DerivationPath::from_str(path).map_err(|_| CommonError::ImkeyPathIllegal)?;
    Ok(())
}

pub fn check_path_max_five_depth(path: &str) -> Result<()> {
    check_path_validity(path)
}

pub fn get_account_path(path: &str) -> Result<String> {
    // example: m/44'/60'/0'/0/0
    let _ = bitcoin::util::bip32::DerivationPath::from_str(path)?;
    let mut children: Vec<&str> = path.split('/').collect();

    ensure!(children.len() >= 4, format!("{} path is too short", path));

    while children.len() > 4 {
        children.remove(children.len() - 1);
    }
    Ok(children.join("/"))
}

/**
get parent public key path
 */
pub fn get_parent_path(path: &str) -> Result<&str> {
    let path = path.trim_end_matches('/');
    let end = path.rfind('/').ok_or(CommonError::ImkeyPathIllegal)?;
    Ok(&path[..end])
}

#[cfg(test)]
mod test {
    use crate::path::check_path_validity;

    #[test]
    fn check_path_validity_test() {
        assert!(check_path_validity("m/44'/0'/0'").is_ok());
        assert!(check_path_validity("m/44a'/0'/0'").is_err());
        assert!(check_path_validity("m/44'/0'/0'/0'/0'").is_ok());
        assert!(check_path_validity("m/44'/0'/0'/0'/0'/0'").is_err());
    }
}

/// Validate a complete BIP44-family signing path, never an account or root key.
/// Coin and purpose allowlists belong to the calling chain's signing policy.
pub fn validate_bip44_signing_path(path: &str, coin_types: &[u32], purposes: &[u32]) -> Result<()> {
    if !path.starts_with("m/") {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    let path = DerivationPath::from_str(path).map_err(|_| CommonError::ImkeyPathIllegal)?;
    match path.as_ref() {
        [ChildNumber::Hardened { index: purpose }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { .. }, ChildNumber::Normal { index: change }, ChildNumber::Normal { .. }]
            if purposes.contains(purpose) && coin_types.contains(coin) && *change <= 1 =>
        {
            Ok(())
        }
        _ => Err(CommonError::ImkeyPathIllegal.into()),
    }
}

pub fn validate_btc_signing_path(path: &str, chain: &str, network: &str) -> Result<()> {
    let coin = match chain {
        "BITCOIN" | "OMNI" => 0,
        "LITECOIN" => 2,
        "DOGECOIN" => 3,
        "BITCOINCASH" => 145,
        _ => return Err(CommonError::ImkeyPathIllegal.into()),
    };
    let coins = match network {
        "MAINNET" => vec![coin],
        // Historical wallets also derive test-network addresses using the
        // chain's normal coin type. Preserve those accounts while rejecting
        // paths belonging to unrelated chains.
        "TESTNET" => vec![coin, 1],
        _ => return Err(CommonError::ImkeyPathIllegal.into()),
    };
    validate_bip44_signing_path(path, &coins, &[44, 49, 84, 86])
}

pub fn validate_same_bip44_account(path: &str, account: &str) -> Result<()> {
    let path = DerivationPath::from_str(path).map_err(|_| CommonError::ImkeyPathIllegal)?;
    let account = DerivationPath::from_str(account).map_err(|_| CommonError::ImkeyPathIllegal)?;
    match (path.as_ref().get(1..3), account.as_ref().get(1..3)) {
        (Some(left), Some(right)) if left == right => Ok(()),
        _ => Err(CommonError::ImkeyPathIllegal.into()),
    }
}

/// Resolve account-relative paths without allowing an empty value to become a
/// root signing key. The signing policy validates the final chain and account.
pub fn resolve_derivation_path(account_path: &str, derived_path: &str) -> Result<String> {
    if derived_path.is_empty() {
        return Ok(String::new());
    }
    let derived_path = derived_path.trim_end_matches('/');
    if derived_path.starts_with("m/") || derived_path.starts_with("M/") {
        let path = format!("m{}", &derived_path[1..]);
        DerivationPath::from_str(&path)?;
        return Ok(path);
    }
    let account = get_account_path(account_path.trim_end_matches('/'))?;
    let path = format!("{account}/{derived_path}");
    DerivationPath::from_str(&path)?;
    Ok(path)
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
