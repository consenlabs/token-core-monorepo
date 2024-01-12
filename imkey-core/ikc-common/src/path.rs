use crate::error::CommonError;
use crate::Result;
use regex::Regex;
use std::str::FromStr;

pub fn check_path_validity(path: &str) -> Result<()> {
    //check depth and length
    let strings: Vec<&str> = path.split("/").collect();
    let depth = strings.len();
    if depth < 2 || depth > 10 {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    Ok(())
}

pub fn check_path_max_five_depth(path: &str) -> Result<()> {
    //check depth and length
    let strings: Vec<&str> = path.split("/").collect();
    let depth = strings.len();
    if depth < 2 || depth > 6 {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    Ok(())
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
