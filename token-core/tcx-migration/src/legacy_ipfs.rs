use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use tcx_constants::{coin_info_from_param, CurveType};
use tcx_crypto::{Crypto, EncPair, Key};
use tcx_keystore::identity::Identity;
use tcx_keystore::keystore::{IdentityNetwork, Keystore, Metadata, Store};
use tcx_keystore::{
    fingerprint_from_private_key, fingerprint_from_seed, mnemonic_to_seed, Address, HdKeystore,
    PrivateKeystore, Result, Source,
};
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, TypedPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpfsInfo {
    pub identifier: String,
    pub ipfs_id: String,
    pub enc_key: String,
}

pub fn read_legacy_ipfs_info(filepath: &str) -> Result<IpfsInfo> {
    let mut identify_file = fs::File::open(&filepath)?;

    let mut json_str = String::new();
    identify_file.read_to_string(&mut json_str)?;
    let ipfs_info: IpfsInfo = serde_json::from_str(&json_str)?;
    Ok(ipfs_info)
}

#[cfg(test)]
mod tests {
    use super::read_legacy_ipfs_info;
    #[test]
    fn test_scan_tcx_legacy_keystores() {
        let ipfs_info = read_legacy_ipfs_info("../test-data/wallets/identity.json").unwrap();
        assert_eq!(
            ipfs_info.identifier,
            "im18MDKM8hcTykvMmhLnov9m2BaFqsdjoA7cwNg"
        );
        assert_eq!(
            ipfs_info.ipfs_id,
            "QmSTTidyfa4np9ak9BZP38atuzkCHy4K59oif23f4dNAGU"
        );
        assert_eq!(
            ipfs_info.enc_key,
            "9513617c9b398edebfb46080a8f0cf6cab6763866bb06daa63503722bea78907"
        );
    }
}
