use tcx_crypto::aes::{cbc, ctr};
use tcx_crypto::{Error, Result};

type LegacyAes = fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>>;

#[test]
fn aes_preserves_anyhow_signatures_and_product_errors() {
    let functions: [LegacyAes; 4] = [
        ctr::encrypt_nopadding,
        ctr::decrypt_nopadding,
        cbc::encrypt_pkcs7,
        cbc::decrypt_pkcs7,
    ];
    let valid = [0u8; 16];
    for function in functions {
        for (key, iv) in [(&valid[..15], &valid[..]), (&valid[..], &valid[..15])] {
            let result: anyhow::Result<Vec<u8>> = function(b"TokenCoreX", key, iv);
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "invalid_key_iv_length");
            assert_eq!(
                error.downcast_ref::<Error>(),
                Some(&Error::InvalidKeyIvLength)
            );
        }
    }
}

#[test]
fn aes_preserves_ciphertext_vectors_and_rejects_malformed_cbc() {
    let key = hex::decode("01020304010203040102030401020304").unwrap();
    let plaintext = b"TokenCoreX";
    for (encrypt, decrypt, expected) in [
        (
            ctr::encrypt_nopadding as LegacyAes,
            ctr::decrypt_nopadding as LegacyAes,
            "e19e6c5923d33c587cf8",
        ),
        (
            cbc::encrypt_pkcs7 as LegacyAes,
            cbc::decrypt_pkcs7 as LegacyAes,
            "13d567987d7eced9c2154551bc37bc5f",
        ),
    ] {
        let encrypted = encrypt(plaintext, &key, &key).unwrap();
        assert_eq!(hex::encode(&encrypted), expected);
        assert_eq!(decrypt(&encrypted, &key, &key).unwrap(), plaintext);
    }
    let error = cbc::decrypt_pkcs7(&[0u8; 15], &key, &key).unwrap_err();
    assert_eq!(error.to_string(), "invalid_ciphertext");
    assert_eq!(
        error.downcast_ref::<Error>(),
        Some(&Error::InvalidCiphertext)
    );
}
