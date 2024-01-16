use crate::api::{AccountResponse, DeriveAccountsParam, DeriveAccountsResult};
use crate::message_handler::encode_message;
use crate::Result;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Network;
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
use ikc_common::aes::cbc::encrypt_pkcs7;
use ikc_common::path::get_account_path;
use ikc_common::utility::{
    get_ext_version, to_ss58check_with_version, uncompress_pubkey_2_compress,
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
            ..Default::default()
        };

        let ext_public_key = match derivation.chain_type.as_str() {
            "BITCOIN" | "LITECOIN" => {
                let network = match derivation.network.as_str() {
                    "MAINNET" => Network::Bitcoin,
                    "TESTNET" => Network::Testnet,
                    _ => Network::Testnet,
                };

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
                CosmosAddress::get_xpub(&account_path)?
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

                let network = Network::from_str(&derivation.network.to_lowercase())?;
                FilecoinAddress::get_xpub(network, &account_path)?
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
                let network = Network::from_str(&derivation.network.to_lowercase())?;
                CkbAddress::get_xpub(network, &account_path)?
            }
            "EOS" => {
                let public_key = EosPubkey::get_sub_pubkey(&derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key[..130]);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = EosPubkey::get_pubkey(&derivation.path)?;
                EosPubkey::get_xpub(&account_path)?
            }
            "BITCOINCASH" => {
                let network = match derivation.network.as_str() {
                    "MAINNET" => Network::Bitcoin,
                    "TESTNET" => Network::Testnet,
                    _ => Network::Testnet,
                };
                let public_key = BchAddress::get_pub_key(network, &derivation.path)?;
                let public_key = uncompress_pubkey_2_compress(&public_key);
                account_rsp.public_key = format!("0x{}", public_key);
                account_rsp.address = BchAddress::get_address(network, &derivation.path)?;
                BtcAddress::get_xpub(network, &account_path)?
            }
            _ => return Err(format_err!("unsupported_chain_type")),
        };

        if !ext_public_key.is_empty() {
            let extended_pub_key = ExtendedPubKey::from_str(&ext_public_key)?;
            let ext_version = get_ext_version(&derivation.network, &account_path)?;
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

fn encrypt_xpub(xpub: &str) -> Result<String> {
    let key = ikc_common::XPUB_COMMON_KEY_128.read();
    let iv = ikc_common::XPUB_COMMON_IV.read();
    let key_bytes = hex::decode(&*key)?;
    let iv_bytes = hex::decode(&*iv)?;
    let encrypted = encrypt_pkcs7(xpub.as_bytes(), &key_bytes, &iv_bytes)?;
    Ok(base64::encode(encrypted))
}
