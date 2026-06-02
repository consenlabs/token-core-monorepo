use crate::error::CommonError;
use crate::Result;

fn normalize_path(path: &str) -> &str {
    wallet_core_common::path::normalize_path(path, true)
}

pub fn check_path_validity(path: &str) -> Result<()> {
    let path = normalize_path(path);
    let depth = path.split('/').count();
    if depth < 3 || depth > 6 {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    wallet_core_common::path::validate_bip32_path(path)
        .map_err(|_| CommonError::ImkeyPathIllegal)?;
    Ok(())
}

pub fn check_path_max_five_depth(path: &str) -> Result<()> {
    let path = normalize_path(path);
    let depth = path.split('/').count();
    if depth < 3 || depth > 6 {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    wallet_core_common::path::validate_bip32_path(path)
        .map_err(|_| CommonError::ImkeyPathIllegal)?;
    Ok(())
}

pub fn get_account_path(path: &str) -> Result<String> {
    // example: m/44'/60'/0'/0/0
    wallet_core_common::path::account_path(
        path,
        wallet_core_common::path::AccountPathOptions::IMKEY_COMPAT,
    )
    .map_err(Into::into)
}

/**
get parent public key path
 */
pub fn get_parent_path(path: &str) -> Result<&str> {
    wallet_core_common::path::parent_path(path).ok_or_else(|| CommonError::ImkeyPathIllegal.into())
}

#[cfg(test)]
mod test {
    use crate::path::{check_path_max_five_depth, check_path_validity, get_account_path};

    #[test]
    fn check_path_validity_test() {
        assert!(check_path_validity("m/44'/0'/0'").is_ok());
        assert!(check_path_validity("m/44a'/0'/0'").is_err());
        assert!(check_path_validity("m/44'/0'/0'/0'/0'").is_ok());
        assert!(check_path_validity("m/44'/0'/0'/0'/0'/0'").is_err());
    }

    #[test]
    fn trailing_slash_is_normalized_consistently_test() {
        let path = "m/44'/0'/0'/0/0/";

        assert!(check_path_validity(path).is_ok());
        assert!(check_path_max_five_depth(path).is_ok());
        assert_eq!(get_account_path(path).unwrap(), "m/44'/0'/0'");
    }
}
