use crate::error::CommonError;
use crate::Result;
use bitcoin::util::bip32::DerivationPath;
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
