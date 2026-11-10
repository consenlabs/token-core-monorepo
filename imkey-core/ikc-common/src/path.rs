use crate::error::CommonError;
use crate::Result;
use wallet_core_common::path::{self, AccountPathOptions, PathError};

pub fn check_path_validity(path: &str) -> Result<()> {
    path::check_path_validity(path).map_err(|_| CommonError::ImkeyPathIllegal.into())
}

pub fn check_path_max_five_depth(path: &str) -> Result<()> {
    path::check_path_max_five_depth(path).map_err(|_| CommonError::ImkeyPathIllegal.into())
}

pub fn get_account_path(path: &str) -> Result<String> {
    ensure!(
        path::normalize_path(path, true).starts_with("m/"),
        CommonError::ImkeyPathIllegal
    );
    path::account_path(path, AccountPathOptions::IMKEY_COMPAT).map_err(|err| match err {
        // Keep the original parser error available to existing callers.
        PathError::InvalidBip32Path(err) => err.into(),
        err => anyhow!("{}", err),
    })
}

pub fn get_parent_path(path: &str) -> Result<&str> {
    path::parent_path(path).ok_or_else(|| CommonError::ImkeyPathIllegal.into())
}
