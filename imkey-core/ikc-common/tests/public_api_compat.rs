use ikc_common::curve::CurveType;
use ikc_common::error::CommonError;
use ikc_common::hex::{FromHex, ToHex};
use ikc_common::path::{
    check_path_max_five_depth, check_path_validity, get_account_path, get_parent_path,
};
use std::str::FromStr;

struct LegacyBytes(Vec<u8>);

#[test]
fn aes_preserves_anyhow_signatures_and_product_errors() {
    use ikc_common::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};

    type LegacyAes = fn(&[u8], &[u8], &[u8]) -> ikc_common::Result<Vec<u8>>;
    let functions: [LegacyAes; 2] = [encrypt_pkcs7, decrypt_pkcs7];
    let valid = [0u8; 16];
    for function in functions {
        for (key, iv) in [(&valid[..15], &valid[..]), (&valid[..], &valid[..15])] {
            let result: anyhow::Result<Vec<u8>> = function(b"TokenCoreX", key, iv);
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "invalid_key_iv_length");
            assert_eq!(
                error.downcast_ref::<CommonError>(),
                Some(&CommonError::InvalidKeyIvLength)
            );
        }
    }
}

#[test]
fn aes_preserves_ciphertext_vector_and_rejects_malformed_cbc() {
    use ikc_common::aes::cbc::{decrypt_pkcs7, encrypt_pkcs7};

    let key = hex::decode("01020304010203040102030401020304").unwrap();
    let plaintext = b"TokenCoreX";
    let encrypted = encrypt_pkcs7(plaintext, &key, &key).unwrap();
    assert_eq!(hex::encode(&encrypted), "13d567987d7eced9c2154551bc37bc5f");
    assert_eq!(decrypt_pkcs7(&encrypted, &key, &key).unwrap(), plaintext);
    let error = decrypt_pkcs7(&[0u8; 15], &key, &key).unwrap_err();
    assert_eq!(error.to_string(), "invalid_ciphertext");
}

impl FromHex for LegacyBytes {
    fn from_hex<T: AsRef<[u8]>>(value: T) -> ikc_common::Result<Self> {
        Vec::from_hex(value).map(Self)
    }
}

#[test]
fn legacy_module_traits_and_anyhow_result_compile() {
    let bytes: ikc_common::Result<Vec<u8>> = Vec::from_hex("0102");
    assert_eq!(bytes.unwrap().to_hex(), "0102");
    assert_eq!(LegacyBytes::from_hex_auto("0X0102").unwrap().0, [1, 2]);
    let _: ikc_common::Result<Vec<u8>> = <Vec<u8> as ikc_common::FromHex>::from_hex("00");
    assert_eq!(ikc_common::ToHex::to_hex(&[0u8]), "00");
    let curve: ikc_common::CurveType = CurveType::SECP256k1;
    assert_eq!(curve.as_str(), "secp256k1");
    assert_eq!(
        Vec::from_hex("zz").unwrap_err().to_string(),
        "Invalid character 'z' at position 0"
    );
}

#[test]
fn account_path_preserves_short_path_and_parser_errors() {
    for path in ["m/44'", "m/44'/0'/"] {
        assert_eq!(
            get_account_path(path).unwrap_err().to_string(),
            format!("{} path is too short", path.trim_end_matches('/'))
        );
    }
    for path in ["m/44a'/0'/0'", "m/44'/a", "m//0'/0'"] {
        let expected = bitcoin::bip32::DerivationPath::from_str(path).unwrap_err();
        let actual = get_account_path(path).unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            actual.downcast_ref::<bitcoin::bip32::Error>(),
            Some(&expected)
        );
    }
}

#[test]
fn imkey_path_wrappers_require_root_and_keep_trailing_slashes() {
    for path in [
        "44'/0'/0'",
        "44'/0'/0'/0/0/",
        "n/44'/60'/0'",
        "M/44'/60'/0'",
        "m/44a'/0'/0'",
        "m",
        "m/",
        "",
    ] {
        for check in [check_path_validity, check_path_max_five_depth] {
            let result: ikc_common::Result<()> = check(path);
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "imkey_path_illegal");
            assert_eq!(
                error.downcast_ref::<CommonError>(),
                Some(&CommonError::ImkeyPathIllegal)
            );
        }
        assert!(get_account_path(path).is_err());
    }
    for path in [
        "44'/60'/0'/0/7",
        "44'/60'/0'",
        "n/44'/60'/0'",
        "M/44'/60'/0'",
        "m",
        "m/",
        "",
    ] {
        let error = get_account_path(path).unwrap_err();
        assert_eq!(error.to_string(), "imkey_path_illegal");
        assert_eq!(
            error.downcast_ref::<CommonError>(),
            Some(&CommonError::ImkeyPathIllegal)
        );
    }
    for path in ["m/44'/0'", "m/44'/0'/0'/0/0/"] {
        assert!(check_path_validity(path).is_ok());
        assert!(check_path_max_five_depth(path).is_ok());
    }
    let account: ikc_common::Result<String> = get_account_path("m/44'/0'/0'/0/0/");
    assert_eq!(account.unwrap(), "m/44'/0'/0'");
    let parent: ikc_common::Result<&str> = get_parent_path("m/44'/0'/0'/0/0/");
    assert_eq!(parent.unwrap(), "m/44'/0'/0'/0");
    assert_eq!(
        get_parent_path("")
            .unwrap_err()
            .downcast_ref::<CommonError>(),
        Some(&CommonError::ImkeyPathIllegal)
    );
}
