use bitcoin::bip32::DerivationPath;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountPathOptions {
    pub trim_trailing_slash: bool,
    pub require_m_prefix: bool,
}

impl AccountPathOptions {
    pub const STRICT: Self = Self {
        trim_trailing_slash: false,
        require_m_prefix: true,
    };

    pub const IMKEY_COMPAT: Self = Self {
        trim_trailing_slash: true,
        require_m_prefix: false,
    };
}

#[derive(Debug)]
pub enum PathError {
    InvalidBip32Path(bitcoin::bip32::Error),
    PathTooShort(String),
    PathMustStartWithM(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImkeyPathError;

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::InvalidBip32Path(err) => err.fmt(f),
            PathError::PathTooShort(path) => write!(f, "{path} path is too short"),
            PathError::PathMustStartWithM(path) => write!(f, "{path} path must start with m"),
        }
    }
}

impl Error for PathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PathError::InvalidBip32Path(err) => Some(err),
            PathError::PathTooShort(_) | PathError::PathMustStartWithM(_) => None,
        }
    }
}

impl From<bitcoin::bip32::Error> for PathError {
    fn from(err: bitcoin::bip32::Error) -> Self {
        PathError::InvalidBip32Path(err)
    }
}

impl fmt::Display for ImkeyPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("imkey_path_illegal")
    }
}

impl Error for ImkeyPathError {}

pub fn normalize_path(path: &str, trim_trailing_slash: bool) -> &str {
    if trim_trailing_slash {
        path.trim_end_matches('/')
    } else {
        path
    }
}

/// Resolves a UTXO derivation path against its account path.
///
/// Hardware signing APIs historically accept both full paths (`m/.../0/0`) and
/// account-relative paths (`0/0`). Empty paths are preserved because callers
/// use them to indicate that the account-level public key should be used.
pub fn resolve_derivation_path(
    account_path: &str,
    derived_path: &str,
) -> Result<String, PathError> {
    if derived_path.is_empty() {
        return Ok(String::new());
    }

    let derived_path = normalize_path(derived_path, true);
    if derived_path == "m"
        || derived_path == "M"
        || derived_path.starts_with("m/")
        || derived_path.starts_with("M/")
    {
        let normalized = format!("m{}", &derived_path[1..]);
        validate_bip32_path(&normalized)?;
        return Ok(normalized);
    }

    let account_path = normalize_path(account_path, true);
    validate_bip32_path(account_path)?;
    let resolved = format!("{account_path}/{derived_path}");
    validate_bip32_path(&resolved)?;
    Ok(resolved)
}

pub fn validate_depth(path: &str, min_depth: usize, max_depth: usize) -> Result<(), PathError> {
    let depth = path.split('/').count();
    if depth < min_depth || depth > max_depth {
        return Err(PathError::PathTooShort(path.to_string()));
    }
    Ok(())
}

pub fn validate_bip32_path(path: &str) -> Result<(), PathError> {
    DerivationPath::from_str(path)?;
    Ok(())
}

pub fn account_path(path: &str, options: AccountPathOptions) -> Result<String, PathError> {
    let path = normalize_path(path, options.trim_trailing_slash);
    validate_bip32_path(path)?;

    let mut children = path.split('/').collect::<Vec<_>>();
    if options.require_m_prefix && children.first() != Some(&"m") {
        return Err(PathError::PathMustStartWithM(path.to_string()));
    }
    if children.len() < 4 {
        return Err(PathError::PathTooShort(path.to_string()));
    }

    while children.len() > 4 {
        children.remove(children.len() - 1);
    }
    Ok(children.join("/"))
}

pub fn parent_path(path: &str) -> Option<&str> {
    if path.is_empty() {
        return None;
    }

    let normalized = path.trim_end_matches('/');
    let end = normalized.rfind('/')?;
    Some(&normalized[..end])
}

pub fn check_path_validity(path: &str) -> Result<(), ImkeyPathError> {
    check_imkey_path(path)
}

pub fn check_path_max_five_depth(path: &str) -> Result<(), ImkeyPathError> {
    check_imkey_path(path)
}

pub fn get_account_path(path: &str) -> Result<String, ImkeyPathError> {
    account_path(path, AccountPathOptions::IMKEY_COMPAT).map_err(|_| ImkeyPathError)
}

pub fn get_parent_path(path: &str) -> Result<&str, ImkeyPathError> {
    parent_path(path).ok_or(ImkeyPathError)
}

fn check_imkey_path(path: &str) -> Result<(), ImkeyPathError> {
    let path = normalize_path(path, true);
    let depth = path.split('/').count();
    if !(3..=6).contains(&depth) {
        return Err(ImkeyPathError);
    }
    validate_bip32_path(path).map_err(|_| ImkeyPathError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_account_path_with_strict_m_prefix() {
        assert_eq!(
            account_path("m/44'/60'/0'/0/0", AccountPathOptions::STRICT).unwrap(),
            "m/44'/60'/0'"
        );
        assert_eq!(
            account_path("m/44'", AccountPathOptions::STRICT)
                .unwrap_err()
                .to_string(),
            "m/44' path is too short"
        );
        assert_eq!(
            account_path("44'/60'/0'", AccountPathOptions::STRICT)
                .unwrap_err()
                .to_string(),
            "44'/60'/0' path must start with m"
        );
    }

    #[test]
    fn supports_imkey_trailing_slash_compatibility() {
        assert_eq!(
            account_path("m/44'/0'/0'/0/0/", AccountPathOptions::IMKEY_COMPAT).unwrap(),
            "m/44'/0'/0'"
        );
        assert_eq!(parent_path("m/44'/0'/0'/0/0/").unwrap(), "m/44'/0'/0'/0");
    }

    #[test]
    fn validates_imkey_paths_with_legacy_error() {
        assert!(check_path_validity("m/44'/0'/0'").is_ok());
        assert!(check_path_validity("m/44'/0'/0'/0'/0'").is_ok());
        assert_eq!(
            check_path_validity("m/44a'/0'/0'").unwrap_err().to_string(),
            "imkey_path_illegal"
        );
        assert_eq!(
            check_path_validity("m/44'/0'/0'/0'/0'/0'")
                .unwrap_err()
                .to_string(),
            "imkey_path_illegal"
        );
        assert!(check_path_max_five_depth("m/44'/0'/0'/0/0/").is_ok());
        assert_eq!(get_account_path("m/44'/0'/0'/0/0/").unwrap(), "m/44'/0'/0'");
    }

    #[test]
    fn resolves_relative_derivation_paths_against_the_account_path() {
        assert_eq!(
            resolve_derivation_path("m/44'/2'/0'/", "0/0").unwrap(),
            "m/44'/2'/0'/0/0"
        );
        assert_eq!(
            resolve_derivation_path("m/44'/145'/0'", "m/44'/145'/0'/0/1/").unwrap(),
            "m/44'/145'/0'/0/1"
        );
        assert_eq!(resolve_derivation_path("m/44'/0'/0'", "").unwrap(), "");
        assert!(resolve_derivation_path("m/44'/2'/0'", "not-a-path").is_err());
    }
}
