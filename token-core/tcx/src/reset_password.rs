use std::ascii::AsciiExt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use anyhow::anyhow;
use serde_json::Value;

use tcx_constants::{CoinInfo, CurveType};
use tcx_eos::address::EosPublicKeyEncoder;
use tcx_keystore::{fingerprint_from_mnemonic, PublicKeyEncoder};
use tcx_migration::keystore_upgrade::mapping_curve_name;
use tcx_migration::migration::LegacyKeystore;
use tcx_primitive::{Derive, PrivateKey, TypedDeterministicPrivateKey, TypedPrivateKey};

use crate::error_handling::Result;
use crate::filemanager::{LEGACY_WALLET_FILE_DIR, WALLET_FILE_DIR};
use crate::handler::{
    decode_private_key, fingerprint_from_any_format_pk, private_key_to_account_dynamic,
};

fn parse_coin_info_from_legacy_ks(value: Value) -> Result<(CoinInfo, String)> {
    let legacy_ks_ret = serde_json::from_value::<LegacyKeystore>(value);
    if let Ok(legacy_ks) = legacy_ks_ret {
        let meta = legacy_ks.im_token_meta.unwrap();
        let chain_str = if meta.chain.is_some() {
            meta.chain.unwrap().to_string()
        } else {
            meta.chain_type.unwrap().to_string()
        };
        let seg_wit = meta.seg_wit.unwrap_or_default();
        let network = meta.network.unwrap_or("MAINNET".to_string());
        // Old btc just save the path prefix
        let (derivation_path, address) = if chain_str.eq_ignore_ascii_case("BITCOIN") {
            if legacy_ks
                .mnemonic_path
                .clone()
                .unwrap_or_default()
                .is_empty()
            {
                ("".to_string(), legacy_ks.address.unwrap_or_default())
            } else {
                (
                    format!("{}/0/0", legacy_ks.mnemonic_path.clone().unwrap()),
                    legacy_ks.address.unwrap_or_default(),
                )
            }
        } else if chain_str.eq_ignore_ascii_case("eos") {
            if let Some(key_pair) = legacy_ks
                .key_path_privates
                .unwrap()
                .iter()
                .find(|x| x.derived_mode.eq(&Some("PATH_DIRECTLY".to_string())))
            {
                (
                    key_pair.path.clone().unwrap_or("".to_string()),
                    key_pair.public_key.clone(),
                )
            } else {
                return Err(anyhow!("eos key not found"));
            }
        } else {
            (
                legacy_ks.mnemonic_path.unwrap_or_default(),
                legacy_ks.address.unwrap_or_default(),
            )
        };

        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin: chain_str.to_string(),
            derivation_path,
            curve: CurveType::SECP256k1,
            network,
            seg_wit,
            hrp: if chain_str.eq_ignore_ascii_case("cosmos") {
                "cosmos".to_string()
            } else {
                "".to_string()
            },
        };
        return Ok((coin_info, address));
    } else {
        return Err(anyhow!("parse legacy keystore failed"));
    }
}

fn parse_coin_info_from_ks(old_ks_id: &str) -> Result<(CoinInfo, String)> {
    let old_path_without_suffix = format!("{}/{}", LEGACY_WALLET_FILE_DIR.read(), old_ks_id);
    let old_path_str = format!("{}.json", old_path_without_suffix);

    let old_path = if Path::new(&old_path_without_suffix).exists() {
        Path::new(&old_path_without_suffix)
    } else {
        Path::new(&old_path_str)
    };

    let mut f = fs::File::open(old_path).expect("open file");
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let json: Value = serde_json::from_str(&contents)?;
    let version = json["version"].as_u64().unwrap_or(0);
    if version != 11001 && version != 11000 {
        parse_coin_info_from_legacy_ks(json)
    } else {
        parse_coin_info_from_legacy_tcx_ks(json)
    }
}

fn parse_coin_info_from_legacy_tcx_ks(legacy_tcx_ks: Value) -> Result<(CoinInfo, String)> {
    if let Some(account_json) = legacy_tcx_ks["activeAccounts"]
        .as_array()
        .expect("tcx keystore missing accounts")
        .first()
    {
        let old_curve_name = account_json["curve"]
            .as_str()
            .expect("activeAccounts need contains curve");
        let new_curve_name = mapping_curve_name(&old_curve_name);
        let curve = CurveType::from_str(&new_curve_name);
        let coin = account_json["coin"]
            .as_str()
            .expect("activeAccounts need contains chainType")
            .to_string();
        let derivation_path = account_json["derivationPath"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let network = account_json["network"]
            .as_str()
            .unwrap_or("MAINNET")
            .to_string();

        let address = account_json["address"]
            .as_str()
            .expect("activeAccounts need contains address")
            .to_string();

        let seg_wit = account_json["segWit"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let coin_info = CoinInfo {
            chain_id: "".to_string(),
            coin,
            derivation_path,
            curve,
            network,
            seg_wit,
            hrp: "".to_string(),
        };
        return Ok((coin_info, address));
    } else {
        return Err(anyhow!("tcx keystore missing accounts"));
    }
}

fn read_json_from_file(file_path: &Path) -> Result<Value> {
    let mut f = fs::File::open(file_path).expect("open file");
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let value: Value = serde_json::from_str(&contents)?;
    return Ok(value);
}

pub(crate) fn assert_seed_equals(overwrite_id: &str, input: &str, is_mnemonic: bool) -> Result<()> {
    if overwrite_id.is_empty() {
        return Ok(());
    }

    let file_path = format!("{}/{}.json", WALLET_FILE_DIR.read(), overwrite_id);
    let migrated_ks_path = Path::new(&file_path);
    if migrated_ks_path.exists() {
        let ks_json = read_json_from_file(migrated_ks_path)?;
        let fingerprint_in_ks = ks_json["sourceFingerprint"]
            .as_str()
            .expect("fingerprint must in new ks");
        let fp_form_user = if is_mnemonic {
            fingerprint_from_mnemonic(&input)?
        } else {
            fingerprint_from_any_format_pk(&input)?
        };
        if fp_form_user.eq_ignore_ascii_case(fingerprint_in_ks) {
            return Ok(());
        } else {
            return Err(anyhow!("seed_not_equals"));
        }
    } else {
        let (coin_info, address) = parse_coin_info_from_ks(overwrite_id)?;
        let secret_key: Vec<u8> = if is_mnemonic {
            let valid_mnemonic = &input.split_whitespace().collect::<Vec<&str>>().join(" ");
            let tdp: TypedDeterministicPrivateKey =
                TypedDeterministicPrivateKey::from_mnemonic(coin_info.curve, &valid_mnemonic)?;
            let child_key = tdp.derive(&coin_info.derivation_path)?;
            child_key.private_key().to_bytes()
        } else {
            decode_private_key(&input)?.bytes
        };

        // EOS can only compare public key
        let calc_address = if coin_info.coin.eq_ignore_ascii_case("EOS") {
            let tdp = TypedPrivateKey::from_slice(CurveType::SECP256k1, &secret_key)?;
            EosPublicKeyEncoder::encode(&tdp.public_key(), &coin_info)
        } else {
            Ok(private_key_to_account_dynamic(&coin_info, &secret_key)?.address)
        }?;
        return if strip_0x_prefix(&calc_address).eq_ignore_ascii_case(&strip_0x_prefix(&address)) {
            Ok(())
        } else {
            Err(anyhow!("seed_not_equals"))
        };
    }
}

fn strip_0x_prefix(addr: &str) -> String {
    if addr.to_lowercase().starts_with("0x") {
        addr[2..].to_string()
    } else {
        addr.to_string()
    }
}
