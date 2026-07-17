use crate::constants::DEFAULT_TSM_URL;
use crate::error::CommonError;
use crate::Result;
use http::Uri;
use parking_lot::RwLock;

const MAX_TSM_URL_LENGTH: usize = 2_048;

lazy_static! {
    static ref TSM_ENDPOINT: TsmEndpoint = TsmEndpoint::default();
}

#[derive(Default)]
struct TsmEndpoint {
    base_url: RwLock<Option<String>>,
}

impl TsmEndpoint {
    fn configure(&self, value: &str) -> Result<()> {
        let normalized = normalize_tsm_url(value, false)?;
        let mut configured = self.base_url.write();
        match configured.as_ref() {
            Some(current) if current == &normalized => Ok(()),
            Some(_) => Err(CommonError::TsmUrlAlreadyConfigured.into()),
            None => {
                *configured = Some(normalized);
                Ok(())
            }
        }
    }

    fn resolve(&self) -> String {
        self.base_url
            .write()
            .get_or_insert_with(|| DEFAULT_TSM_URL.to_string())
            .clone()
    }
}

/// Configures the process-wide TSM base URL.
///
/// Repeating the same value is idempotent. Switching to a different server in
/// the same process is rejected so an active wallet session cannot be silently
/// redirected after initialization.
pub fn configure_tsm_url(value: &str) -> Result<()> {
    TSM_ENDPOINT.configure(value)
}

pub fn tsm_base_url() -> String {
    TSM_ENDPOINT.resolve()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_uri(action: &str) -> Result<Uri> {
    request_uri_with_base(&tsm_base_url(), action)
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn request_uri_with_base(base_url: &str, action: &str) -> Result<Uri> {
    if !action.starts_with('/') || action.starts_with("//") || action.contains(['?', '#']) {
        return Err(CommonError::InvalidTsmUrl.into());
    }
    format!("{base_url}{action}")
        .parse()
        .map_err(|_| CommonError::InvalidTsmUrl.into())
}

fn normalize_tsm_url(value: &str, allow_http_loopback: bool) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_TSM_URL_LENGTH || value.contains('#') {
        return Err(CommonError::InvalidTsmUrl.into());
    }

    let normalized = value.trim_end_matches('/');
    let uri: Uri = normalized.parse().map_err(|_| CommonError::InvalidTsmUrl)?;
    let scheme = uri.scheme_str().ok_or(CommonError::InvalidTsmUrl)?;
    let authority = uri.authority().ok_or(CommonError::InvalidTsmUrl)?;

    if scheme != "https"
        && !(allow_http_loopback
            && scheme == "http"
            && matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]"))
    {
        return Err(CommonError::TsmUrlRequiresHttps.into());
    }
    if authority.as_str().contains('@') || uri.query().is_some() {
        return Err(CommonError::InvalidTsmUrl.into());
    }

    Ok(normalized.to_string())
}

#[cfg(test)]
pub(crate) fn normalize_test_tsm_url(value: &str) -> Result<String> {
    normalize_tsm_url(value, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn validates_and_normalizes_tsm_urls() {
        assert_eq!(
            "https://example.com:10444/imkey",
            normalize_tsm_url("  https://example.com:10444/imkey/// ", false).unwrap()
        );
        assert_eq!(
            CommonError::TsmUrlRequiresHttps.to_string(),
            normalize_tsm_url("http://example.com/imkey", false)
                .unwrap_err()
                .to_string()
        );
        for invalid in [
            "",
            "https:///imkey",
            "https://user@example.com/imkey",
            "https://example.com/imkey?environment=dev",
            "https://example.com/imkey#fragment",
        ] {
            assert!(
                normalize_tsm_url(invalid, false).is_err(),
                "unexpectedly accepted {}",
                invalid
            );
        }
        assert!(normalize_test_tsm_url("http://127.0.0.1:1234/imkey").is_ok());
    }

    #[test]
    fn configured_url_is_idempotent_and_cannot_be_replaced() {
        let endpoint = TsmEndpoint::default();
        let configured = "https://tsm-config.example.com/imkey";
        endpoint.configure(configured).unwrap();
        endpoint.configure(&format!("{configured}/")).unwrap();
        assert_eq!(configured, endpoint.resolve());
        assert_eq!(
            CommonError::TsmUrlAlreadyConfigured.to_string(),
            endpoint
                .configure("https://other.example.com/imkey")
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn first_request_locks_the_compatibility_fallback() {
        let endpoint = TsmEndpoint::default();
        assert_eq!(DEFAULT_TSM_URL, endpoint.resolve());
        endpoint.configure(DEFAULT_TSM_URL).unwrap();
        assert_eq!(
            CommonError::TsmUrlAlreadyConfigured.to_string(),
            endpoint
                .configure("https://other.example.com/imkey")
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn concurrent_configuration_selects_exactly_one_endpoint() {
        let endpoint = Arc::new(TsmEndpoint::default());
        let barrier = Arc::new(Barrier::new(2));
        let handles = [
            "https://one.example.com/imkey",
            "https://two.example.com/imkey",
        ]
        .map(|base_url| {
            let endpoint = Arc::clone(&endpoint);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                (base_url, endpoint.configure(base_url))
            })
        });

        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(
            1,
            results.iter().filter(|(_, result)| result.is_ok()).count()
        );
        assert_eq!(
            1,
            results
                .iter()
                .filter(|(_, result)| match result {
                    Err(error) => {
                        error.to_string() == CommonError::TsmUrlAlreadyConfigured.to_string()
                    }
                    Ok(()) => false,
                })
                .count()
        );
        assert!(results
            .iter()
            .any(|(base_url, result)| result.is_ok() && *base_url == endpoint.resolve()));
    }

    #[test]
    fn request_actions_cannot_override_the_configured_authority() {
        assert_eq!(
            "https://example.com/imkey/seInfoQuery",
            request_uri_with_base("https://example.com/imkey", "/seInfoQuery")
                .unwrap()
                .to_string()
        );
        assert!(request_uri_with_base("https://example.com/imkey", "//attacker.test").is_err());
        assert!(request_uri_with_base("https://example.com/imkey", "/query?x=1").is_err());
    }
}
