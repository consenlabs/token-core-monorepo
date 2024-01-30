use crate::error_handling::Result;
use crate::message_handler::encode_message;
use anyhow::anyhow;
use coin_ethereum::ethapi::{EthMessageInput, EthTxInput};
use coin_ethereum::transaction::{AccessListItem, Transaction};
use coin_ethereum::types::Action;
use ethereum_types::{Address, H256, U256};
use hex;
use ikc_common::constants::ETH_TRANSACTION_TYPE_EIP1559;
use ikc_common::SignParam;
use prost::Message;
use std::str::FromStr;

pub fn sign_eth_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: EthTxInput = EthTxInput::decode(data).expect("imkey_illegal_param");
    let data_vec = if input.data.starts_with("0x") {
        hex::decode(&input.data[2..]).unwrap()
    } else {
        hex::decode(&input.data).unwrap()
    };

    let mut to = input.to;
    if to.starts_with("0x") {
        to = to[2..].to_string();
    }

    let eth_tx = if input.r#type.to_lowercase() == "0x02"
        || input.r#type.to_lowercase() == "0x2"
        || input.r#type == ETH_TRANSACTION_TYPE_EIP1559
    {
        Transaction {
            nonce: parse_eth_argument(&input.nonce)?,
            gas_price: U256::from(0),
            gas_limit: parse_eth_argument(&input.gas_limit)?,
            to: Action::Call(Address::from_str(&to).unwrap()),
            value: parse_eth_argument(&input.value)?,
            data: Vec::from(data_vec.as_slice()),
            tx_type: ETH_TRANSACTION_TYPE_EIP1559.to_string(),
            max_fee_per_gas: Some(parse_eth_argument(&input.max_fee_per_gas)?),
            max_priority_fee_per_gas: Some(parse_eth_argument(&input.max_priority_fee_per_gas)?),
            access_list: {
                let mut access_list: Vec<AccessListItem> = Vec::new();
                for access in input.access_list {
                    let item = AccessListItem {
                        address: Address::from_str(remove_0x(&access.address)).unwrap(),
                        storage_keys: {
                            let mut storage_keys: Vec<H256> = Vec::new();
                            for key in access.storage_keys {
                                storage_keys
                                    .push(Transaction::hexstring_to_hex256(remove_0x(&key)));
                            }
                            storage_keys
                        },
                    };
                    access_list.push(item);
                }
                access_list
            },
        }
    } else {
        Transaction {
            nonce: parse_eth_argument(&input.nonce)?,
            gas_price: parse_eth_argument(&input.gas_price)?,
            gas_limit: parse_eth_argument(&input.gas_limit)?,
            to: Action::Call(Address::from_str(&to).unwrap()),
            value: parse_eth_argument(&input.value)?,
            data: Vec::from(data_vec.as_slice()),
            tx_type: input.r#type,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: vec![],
        }
    };

    let chain_id_parsed = input.chain_id.parse::<u64>();
    let chain_id = match chain_id_parsed {
        Ok(id) => id,
        Err(_error) => {
            if input.chain_id.to_lowercase().starts_with("0x") {
                let without_prefix = &input.chain_id.trim_start_matches("0x");
                u64::from_str_radix(without_prefix, 16).unwrap()
            } else {
                u64::from_str_radix(&input.chain_id, 16).unwrap()
            }
        }
    };

    let tx_out = eth_tx.sign(
        Some(chain_id),
        &sign_param.path,
        &sign_param.payment,
        &sign_param.receiver,
        &sign_param.sender,
        &sign_param.fee,
    )?;
    encode_message(tx_out)
}

fn parse_eth_argument(str: &str) -> Result<U256> {
    if str.to_lowercase().starts_with("0x") {
        U256::from_str(&str[2..].to_string()).map_err(|_err| anyhow!("unpack eth argument error"))
    } else {
        U256::from_dec_str(str).map_err(|_err| anyhow!("unpack eth argument dec error"))
    }
}

fn remove_0x(str: &str) -> &str {
    if str.to_lowercase().starts_with("0x") {
        &str[2..]
    } else {
        &str
    }
}

pub fn sign_eth_message(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: EthMessageInput = EthMessageInput::decode(data).expect("imkey_illegal_param");
    let signed = Transaction::sign_message(input, sign_param)?;
    encode_message(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_signer::sign_eth_transaction;
    use coin_ethereum::ethapi::{AccessList, EthTxInput, EthTxOutput};
    use ethereum_types::U256;
    use hex;
    use ikc_common::constants;
    use ikc_device::device_binding::bind_test;

    use std::str::FromStr;

    #[test]
    fn u256_from_str() {
        let ret = U256::from_str("18").unwrap();
        assert_eq!(U256::from(24i128), ret);
    }

    #[test]
    fn sign_tx_int_chainid_test() {
        bind_test();
        let path = "m/44'/60'/0'/0/0".to_string();
        let data = hex::decode("0a0134120a353030303030303030301a0730783430343964222a3078396564306335333530626331376666343535323937323265623037353830666635363463336137382a0c3078653864346135313030303a0131").unwrap();
        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path,
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.000001 BNB".to_string(),
            receiver: "0x9Ed0c5350Bc17FF45529722eb07580Ff564c3a78".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.001316 ETH".to_string(),
        };
        let _x = sign_eth_transaction(data.as_slice(), &sign_param).unwrap();
        println!("sign");
    }

    #[test]
    fn sign_tx_hex_chainid_test() {
        bind_test();
        let path = "m/44'/60'/0'/0/0".to_string();
        let data = hex::decode("0a0134120a353030303030303030301a0730783430343964222a3078396564306335333530626331376666343535323937323265623037353830666635363463336137382a0c3078653864346135313030303a0430783338").unwrap();
        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path,
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.000001 BNB".to_string(),
            receiver: "0x9Ed0c5350Bc17FF45529722eb07580Ff564c3a78".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.001316 ETH".to_string(),
        };
        let _x = sign_eth_transaction(data.as_slice(), &sign_param).unwrap();
        println!("sign");
    }

    #[test]
    fn sign_tx_hex_chainid_test2() {
        bind_test();
        let path = "m/44'/60'/0'/0/0".to_string();
        let data = hex::decode("0a0134120a353030303030303030301a0730783430343964222a3078396564306335333530626331376666343535323937323265623037353830666635363463336137382a0c3078653864346135313030303a024133").unwrap();
        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path,
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.000001 BNB".to_string(),
            receiver: "0x9Ed0c5350Bc17FF45529722eb07580Ff564c3a78".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.001316 ETH".to_string(),
        };
        let _x = sign_eth_transaction(data.as_slice(), &sign_param).unwrap();
        println!("sign");
    }

    #[test]
    fn sign_tx_error_chainid_test() {
        bind_test();
        let path = "m/44'/60'/0'/0/0".to_string();
        let data = hex::decode("0a0134120a353030303030303030301a0730783430343964222a3078396564306335333530626331376666343535323937323265623037353830666635363463336137382a0c3078653864346135313030303a03787878").unwrap();
        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path,
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.000001 BNB".to_string(),
            receiver: "0x9Ed0c5350Bc17FF45529722eb07580Ff564c3a78".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.001316 ETH".to_string(),
        };
        let _x = sign_eth_transaction(data.as_slice(), &sign_param).unwrap();
        println!("sign");
    }

    #[test]
    fn test_sign_eth_transaction_eip1559() {
        bind_test();

        let tx = EthTxInput {
            nonce: "4".to_string(),
            gas_price: "".to_string(),
            gas_limit: "54".to_string(),
            to: "d5539a0e4d27ebf74515fc4acb38adcc3c513f25".to_string(),
            value: "64".to_string(),
            data: "f579eebd8a5295c6f9c86e".to_string(),
            chain_id: "276".to_string(),
            r#type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: "963240322143".to_string(),
            max_priority_fee_per_gas: "28710".to_string(),
            access_list: vec![AccessList {
                address: "70b361fc3a4001e4f8e4e946700272b51fe4f0c4".to_string(),
                storage_keys: vec![
                    "8419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63".to_string(),
                    "8a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3".to_string(),
                    "897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab9".to_string(),
                ],
            }],
        };

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 ETH".to_string(),
            receiver: "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.0032 ether".to_string(),
        };

        let data = encode_message(tx).unwrap();
        let res = sign_eth_transaction(&data.as_ref(), &sign_param);
        let output: EthTxOutput =
            EthTxOutput::decode(res.unwrap().as_ref()).expect("imkey_illegal_param");
        assert_eq!(
            output.signature,
            "02f8f18201140482702685e04598e45f3694d5539a0e4d27ebf74515fc4acb38adcc3c513f25408bf579eebd8a5295c6f9c86ef87cf87a9470b361fc3a4001e4f8e4e946700272b51fe4f0c4f863a08419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63a08a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3a0897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab980a0bacd306ae19a67ffe6a6864b982dda2adc433cea38b13bfc21ca3155f1655bb6a039dad052cbb7c685c4048cafb16df681ce9e554c0cca173620a216935654c00b".to_string()
        );
        assert_eq!(
            output.tx_hash,
            "0xe66abf92ea7b79ec05519444d1f360a121f224e9d6981a41e2ada82f7f50afe9".to_string()
        );
    }

    #[test]
    fn test_sign_eth_transaction_eip1559_no_access_list() {
        bind_test();

        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "".to_string(),
            gas_limit: "14298499".to_string(),
            to: "ef970655297d1234174bcfe31ee803aaa97ad0ca".to_string(),
            value: "11".to_string(),
            data: "ee".to_string(),
            chain_id: "130".to_string(),
            r#type: "0x2".to_string(),
            max_fee_per_gas: "850895266216".to_string(),
            max_priority_fee_per_gas: "69".to_string(),
            access_list: vec![],
        };

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 ETH".to_string(),
            receiver: "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.0032 ether".to_string(),
        };

        let data = encode_message(tx).unwrap();

        let res = sign_eth_transaction(&data.as_ref(), &sign_param);

        let output: EthTxOutput =
            EthTxOutput::decode(res.unwrap().as_ref()).expect("imkey_illegal_param");
        assert_eq!(
            output.signature,
            "02f86a8182084585c61d4f61a883da2d8394ef970655297d1234174bcfe31ee803aaa97ad0ca0b81eec001a043b16ce6f245f8ec1d145e8b1f36bb9f6e7a7fd9030139a8143c3e0e9ccb6e9ca04020e1ae4920cfbf7c88e7be6a73751bb28d9bc8e6ecf3c5c989310c5871de8a".to_string()
        );
        assert_eq!(
            output.tx_hash,
            "0xd38f47550c709e39519a3e35024a5ec135a8893890001658f2bd96e60f88fd9a".to_string()
        );
    }

    #[test]
    fn test_sign_eth_transaction_eip1559_multi_access_list() {
        bind_test();

        let tx = EthTxInput {
            nonce: "1".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "6f4ecd70932d65ac08b56db1f4ae2da4391f328e".to_string(),
            value: "3490361".to_string(),
            data: "200184c0486d5f082a27".to_string(),
            chain_id: "63".to_string(),
            r#type: "0x02".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![
                AccessList {
                    address: "019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
                    storage_keys: vec![],
                },
                AccessList {
                    address: "1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
                    storage_keys: vec![
                        "d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2"
                            .to_string(),
                    ],
                },
                AccessList {
                    address: "f1946eba70f89687d67493d8106f56c90ecba943".to_string(),
                    storage_keys: vec![
                        "b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9"
                            .to_string(),
                        "6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82"
                            .to_string(),
                        "0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064"
                            .to_string(),
                    ],
                },
            ],
        };

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 ETH".to_string(),
            receiver: "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.0032 ether".to_string(),
        };

        let data = encode_message(tx).unwrap();

        let res = sign_eth_transaction(&data.as_ref(), &sign_param);

        let output: EthTxOutput =
            EthTxOutput::decode(res.unwrap().as_ref()).expect("imkey_illegal_param");
        assert_eq!(
            output.signature,
            "02f901413f0181e285faac6c45d88210be946f4ecd70932d65ac08b56db1f4ae2da4391f328e833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0c5dfcb3a472086ca8c29fa31b9a86c40a6bbaeeb9db938c6729305e5f35aaeb1a04a83adc3c02b706c2c3d67de0274aa771b75c2da04c4c21ed0745637a6f937de".to_string()
        );
        assert_eq!(
            output.tx_hash,
            "0xabb4c4b2b6f406b3598b5d8c5e0e7780209a50503ca5350c87ddcb82b5f518ff".to_string()
        );
    }

    #[test]
    fn test_sign_eth_transaction_eip1559_hex_string() {
        bind_test();

        let tx = EthTxInput {
            nonce: "1".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "0x6f4ecd70932d65ac08b56db1f4ae2da4391f328e".to_string(),
            value: "3490361".to_string(),
            data: "200184c0486d5f082a27".to_string(),
            chain_id: "63".to_string(),
            r#type: String::from(constants::ETH_TRANSACTION_TYPE_EIP1559),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![
                AccessList {
                    address: "0x019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
                    storage_keys: vec![],
                },
                AccessList {
                    address: "0x1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
                    storage_keys: vec![
                        "0xd259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2"
                            .to_string(),
                    ],
                },
                AccessList {
                    address: "0xf1946eba70f89687d67493d8106f56c90ecba943".to_string(),
                    storage_keys: vec![
                        "0xb3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9"
                            .to_string(),
                        "0x6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82"
                            .to_string(),
                        "0x0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064"
                            .to_string(),
                    ],
                },
            ],
        };

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 ETH".to_string(),
            receiver: "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.0032 ether".to_string(),
        };

        let data = encode_message(tx).unwrap();

        let res = sign_eth_transaction(&data.as_ref(), &sign_param);

        let output: EthTxOutput =
            EthTxOutput::decode(res.unwrap().as_ref()).expect("imkey_illegal_param");
        assert_eq!(
            output.signature,
            "02f901413f0181e285faac6c45d88210be946f4ecd70932d65ac08b56db1f4ae2da4391f328e833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0c5dfcb3a472086ca8c29fa31b9a86c40a6bbaeeb9db938c6729305e5f35aaeb1a04a83adc3c02b706c2c3d67de0274aa771b75c2da04c4c21ed0745637a6f937de".to_string()
        );
        assert_eq!(
            output.tx_hash,
            "0xabb4c4b2b6f406b3598b5d8c5e0e7780209a50503ca5350c87ddcb82b5f518ff".to_string()
        );
    }

    #[test]
    fn test_sign_eth_transaction_legacy() {
        bind_test();

        /*let tx = EthTxInputLegacy {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "28".to_string(),
        };*/

        let sign_param = SignParam {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "0.01 ETH".to_string(),
            receiver: "0xE6F4142dfFA574D1d9f18770BF73814df07931F3".to_string(),
            sender: "0x6031564e7b2F5cc33737807b2E58DaFF870B590b".to_string(),
            fee: "0.0032 ether".to_string(),
        };

        let data = hex::decode("0a0138120b32303030303030303030381a063138393030302228333533353335333533353335333533353335333533353335333533353335333533353335333533352a033531323a023238").unwrap();
        let res = sign_eth_transaction(&data.as_ref(), &sign_param);
        let output: EthTxOutput =
            EthTxOutput::decode(res.unwrap().as_ref()).expect("imkey_illegal_param");
        assert_eq!(
            output.signature,
            "f867088504a817c8088302e248943535353535353535353535353535353535353535820200805ba03aa62abb45b77418caf139dda0179aea802c99967b3d690b87d586a87bc805afa02b5ce94f40dc865ca63403e0e5e723e1523884f001573677cd8cec11c7ca332f".to_string()
        );
        assert_eq!(
            output.tx_hash,
            "0x09fa41c4d6b92482506c8c56f65b217cc3398821caec7695683110997426db01".to_string()
        );
    }
}
