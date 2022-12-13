use crate::error::CommonError;
use crate::Result;
use regex::Regex;

pub fn check_path_validity(path: &str) -> Result<()> {
    //check depth and length
    let strings: Vec<&str> = path.split("/").collect();
    let depth = strings.len();
    if depth < 2 || depth > 10 || path.len() > 100 {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    //regx check
    let re = Regex::new(r"^m/[0-9'/]+$").unwrap();
    if !re.is_match(path) {
        return Err(CommonError::ImkeyPathIllegal.into());
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::path::check_path_validity;

    #[test]
    fn check_path_validity_test() {
        assert!(check_path_validity("m/44'/0'/0'").is_ok());
        assert!(check_path_validity("m/44a'/0'/0'").is_err());
    }
}
