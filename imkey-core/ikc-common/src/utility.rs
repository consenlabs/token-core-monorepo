pub use wallet_core_common::utility::{
    bigint_to_byte_vec, encrypt_xpub_with_key_iv, extended_pub_key_derive,
    from_ss58check_with_version, get_xpub_prefix, hex_to_bytes, is_valid_hex, network_convert,
    retrieve_recid, secp256k1_sign, secp256k1_sign_verify, sha256_hash, to_ss58check_with_version,
    uncompress_pubkey_2_compress, utf8_or_hex_to_bytes, version_at_least,
};

use crate::Result;

pub fn encrypt_xpub(xpub: &str) -> Result<String> {
    let key = crate::XPUB_COMMON_KEY_128.read();
    let iv = crate::XPUB_COMMON_IV.read();
    wallet_core_common::utility::encrypt_xpub_with_key_iv(xpub, &key, &iv).map_err(Into::into)
}
