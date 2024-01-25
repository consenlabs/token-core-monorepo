use crate::api::{
    AccountResponse, DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam,
    DeriveSubAccountsResult,
};
use crate::message_handler::encode_message;
use crate::Result;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::bip32::ExtendedPubKey;
use coin_bch::address::BchAddress;
use coin_bitcoin::address::BtcAddress;
use coin_btc_fork::address::BtcForkAddress;
use coin_btc_fork::btc_fork_network::network_from_param;
use coin_ckb::address::CkbAddress;
use coin_cosmos::address::CosmosAddress;
use coin_eos::pubkey::EosPubkey;
use coin_ethereum::address::EthAddress;
use coin_filecoin::address::FilecoinAddress;
use coin_substrate::address::{AddressType, SubstrateAddress};
use coin_tron::address::TronAddress;
use ikc_common::curve::CurveType;
use ikc_common::path::get_account_path;
use ikc_common::utility::{
    encrypt_xpub, extended_pub_key_derive, from_ss58check_with_version, get_xpub_prefix,
    network_convert, to_ss58check_with_version, uncompress_pubkey_2_compress,
};
use prost::Message;
use std::str::FromStr;

pub(crate) fn derive_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveAccountsParam =
        DeriveAccountsParam::decode(data).expect("derive_accounts param");
    let mut account_responses = vec![];
    for derivation in param.derivations {
        let account_path = if "secp256k1".eq(&derivation.curve.to_lowercase()) {
            get_account_path(&derivation.path)?
        } else {
            "".to_string()
        };

        let mut account_rsp = AccountResponse {
            chain_type: derivation.chain_type.to_owned(),
            path: derivation.path.to_owned(),
            curve: derivation.curve,
            seg_wit: derivation.seg_wit.to_owned(),
            ..Default::default()
        };

        let ext_public_key = match derivation.chain_type.as_str() {
            "BITCOIN" | "LITECOIN" => {
                let network = network_convert(derivation.network.as_str());
                let public_key = BtcAddress::get_pub_key(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key);
                account_rsp.public_key = format!("0x{}", public_key);
                let btc_fork_network = network_from_param(
                    &derivation.chain_type,
                    &derivation.network,
                    &derivation.seg_wit,
                )
                .unwrap();
                let address = match derivation.seg_wit.as_str() {
                    "P2WPKH" => BtcForkAddress::p2shwpkh(&btc_fork_network, &derivation.path)?,
                    _ => BtcForkAddress::p2pkh(&btc_fork_network, &derivation.path)?,
                };
                account_rsp.address = address;
                BtcAddress::get_xpub(network, &account_path)?
            }
            "ETHEREUM" => {
                let public_key = EthAddress::get_pub_key(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key[..130]);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = EthAddress::get_address(&derivation.path)?;
                EthAddress::get_xpub(&account_path)?
            }
            "COSMOS" => {
                let public_key = CosmosAddress::get_pub_key(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key[..130]);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = CosmosAddress::get_address(&derivation.path)?;
                CosmosAddress::get_xpub(&account_path)?
            }
            "FILECOIN" => {
                let public_key = FilecoinAddress::get_pub_key(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key[..130]);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address =
                    FilecoinAddress::get_address(&derivation.path, &derivation.network)?;
                FilecoinAddress::get_xpub(&derivation.network, &account_path)?
            }
            "POLKADOT" | "KUSAMA" => {
                let public_key = SubstrateAddress::get_public_key(
                    &derivation.path,
                    &AddressType::from_str(&derivation.chain_type)?,
                )?;
                account_rsp.public_key = format!("0x{}", public_key).to_lowercase();
                account_rsp.address = SubstrateAddress::get_address(
                    &derivation.path,
                    &AddressType::from_str(&derivation.chain_type)?,
                )?;
                "".to_string()
            }
            "TRON" => {
                let public_key = hex::encode(TronAddress::get_pub_key(&derivation.path)?);
                let public_key = uncompress_pubkey_2_compress(&public_key[..130]);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = TronAddress::get_address(&derivation.path)?;
                TronAddress::get_xpub(&account_path)?
            }
            "NERVOS" => {
                let public_key = CkbAddress::get_public_key(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address =
                    CkbAddress::get_address(&derivation.network, &derivation.path)?;
                CkbAddress::get_xpub(&derivation.network, &account_path)?
            }
            "EOS" => {
                account_rsp.public_key = EosPubkey::get_pubkey(&derivation.path)?;
                account_rsp.address = "".to_string();
                EosPubkey::get_xpub(&account_path)?
            }
            "BITCOINCASH" => {
                let network = network_convert(derivation.network.as_str());
                let public_key = BchAddress::get_pub_key(network, &derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = BchAddress::get_address(network, &derivation.path)?;
                BtcAddress::get_xpub(network, &account_path)?
            }
            _ => return Err(anyhow!("unsupported_chain_type")),
        };

        if !ext_public_key.is_empty() {
            let extended_pub_key = ExtendedPubKey::from_str(&ext_public_key)?;
            let ext_version = get_xpub_prefix(&derivation.network);
            let ext_public_key = to_ss58check_with_version(extended_pub_key, &ext_version);
            account_rsp.extended_public_key = ext_public_key.clone();
            account_rsp.encrypted_extended_public_key = encrypt_xpub(&ext_public_key)?;
        }
        account_responses.push(account_rsp);
    }

    encode_message(DeriveAccountsResult {
        accounts: account_responses,
    })
}

pub(crate) fn derive_sub_accounts(data: &[u8]) -> Result<Vec<u8>> {
    let param: DeriveSubAccountsParam =
        DeriveSubAccountsParam::decode(data).expect("derive_accounts_param_error");
    //get xpub
    let curve = CurveType::from_str(&param.curve);
    let xpub = match curve {
        CurveType::SECP256k1 => from_ss58check_with_version(&param.extended_public_key)?,
        _ => return Err(anyhow!("invalid_curve_type")),
    };
    let encrypted_extended_public_key = encrypt_xpub(&param.extended_public_key.to_string())?;
    let mut account = AccountResponse {
        chain_type: param.chain_type.to_owned(),
        curve: param.curve,
        extended_public_key: param.extended_public_key.to_owned(),
        encrypted_extended_public_key,
        seg_wit: param.seg_wit.to_owned(),
        ..Default::default()
    };
    let mut account_responses = vec![];
    for relative_path in param.relative_paths {
        let ext_pub_key = extended_pub_key_derive(&xpub.0, &relative_path)?;
        let pub_key_uncompressed = ext_pub_key.public_key.serialize_uncompressed().to_vec();
        account.public_key = format!("0x{}", ext_pub_key.public_key.serialize().to_hex());
        let address = match param.chain_type.as_str() {
            "ETHEREUM" => EthAddress::from_pub_key(pub_key_uncompressed)?,
            "BITCOIN" | "LITECOIN" => {
                let btc_fork_network =
                    network_from_param(&param.chain_type, &param.network, &param.seg_wit);
                if btc_fork_network.is_none() {
                    return Err(anyhow!("get_btc_fork_network_is_null"));
                }
                BtcForkAddress::from_pub_key(pub_key_uncompressed, btc_fork_network.unwrap())?
            }
            "COSMOS" => CosmosAddress::from_pub_key(pub_key_uncompressed)?,
            "FILECOIN" => FilecoinAddress::from_pub_key(pub_key_uncompressed, &param.network)?,
            "TRON" => TronAddress::from_pub_key(&pub_key_uncompressed)?,
            "NERVOS" => CkbAddress::from_public_key(&param.network, &pub_key_uncompressed)?,
            "EOS" => EosPubkey::from_pub_key(&pub_key_uncompressed)?,
            "BITCOINCASH" => BchAddress::from_pub_key(&pub_key_uncompressed, &param.network)?,
            _ => return Err(anyhow!("unsupported_chain_type")),
        };
        account.address = address;
        account_responses.push(account.clone());
    }

    encode_message(DeriveSubAccountsResult {
        accounts: account_responses,
    })
}

#[cfg(test)]
mod test {
    use crate::api::derive_accounts_param::Derivation;
    use crate::api::{DeriveAccountsParam, DeriveSubAccountsParam};
    use crate::handler::{derive_accounts, derive_sub_accounts};
    use crate::message_handler::encode_message;

    #[test]
    fn test_derive_accounts_exception() {
        let derivations = vec![Derivation {
            chain_type: "TEZOS".to_string(),
            path: "".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "ed25519".to_string(),
            bech32_prefix: "".to_string(),
        }];
        let param = DeriveAccountsParam { derivations };
        let response = derive_accounts(&encode_message(param).unwrap());
        assert!(response.is_err());
        assert_eq!(
            response.err().unwrap().to_string(),
            "unsupported_chain_type"
        );
    }

    #[test]
    fn test_derive_sub_accounts_exception() {
        let param = DeriveSubAccountsParam {
            chain_type: "POLKADOT".to_string(),
            curve: "ed25519".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string()],
            extended_public_key: "".to_string(),
        };
        let response = derive_sub_accounts(&encode_message(param).unwrap());
        assert!(response.is_err());
        assert_eq!(response.err().unwrap().to_string(), "invalid_curve_type");

        let param = DeriveSubAccountsParam{
            chain_type: "POLKADOT".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string()],
            extended_public_key: "xpub6Boii2KSAfEv7EhbBuopXKB2Gshi8kMpTGWyHuY9BHwYA8qPeu7ZYdnnXCuUdednhwyjyK2Z8gJD2AfawgBHp3Kkf2GjBjzEQAyJ3uJ4SuG".to_string(),
        };
        let response = derive_sub_accounts(&encode_message(param).unwrap());
        assert!(response.is_err());
        assert_eq!(
            response.err().unwrap().to_string(),
            "unsupported_chain_type"
        );
    }
}
