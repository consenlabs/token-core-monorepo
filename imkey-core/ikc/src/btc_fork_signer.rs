use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;

use coin_btc_fork::btcforkapi::{BtcForkTxInput, BtcForkTxOutput};
use coin_btc_fork::transaction::BtcForkTransaction;
use ikc_common::coin_info::coin_info_from_param;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: BtcForkTxInput = BtcForkTxInput::decode(data).expect("BtcForkTxInput");
    if input.seg_wit.to_uppercase() == "P2WPKH" {
        sign_segwit_transaction(&input, sign_param)
    } else {
        sign_legacy_transaction(&input, sign_param)
    }
}

pub fn sign_legacy_transaction(param: &BtcForkTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let extra_data = vec![];
    let coin_info = coin_info_from_param(
        &sign_param.chain_type,
        &sign_param.network,
        &param.seg_wit,
        "",
    )
    .unwrap();
    let transaction_req_data = BtcForkTransaction {
        tx_input: param.clone(),
        coin_info,
    };
    let network = if sign_param.network == "TESTNET".to_string() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let signed = transaction_req_data.sign_transaction(network, &sign_param.path, &extra_data)?;
    let tx_sign_result = BtcForkTxOutput {
        signature: signed.signature,
        tx_hash: signed.tx_hash,
        wtx_hash: "".to_string(),
    };

    encode_message(tx_sign_result)
}

pub fn sign_segwit_transaction(param: &BtcForkTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let extra_data = vec![];
    let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "P2WPKH", "").unwrap();
    let transaction_req_data = BtcForkTransaction {
        tx_input: param.clone(),
        coin_info,
    };
    let network = if sign_param.network == "TESTNET".to_string() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let signed =
        transaction_req_data.sign_segwit_transaction(network, &sign_param.path, &extra_data)?;

    let tx_sign_result = BtcForkTxOutput {
        signature: signed.signature,
        tx_hash: signed.tx_hash,
        wtx_hash: "".to_string(),
    };
    encode_message(tx_sign_result)
}

#[cfg(test)]
mod tests {
    use crate::btc_fork_signer::{sign_legacy_transaction, sign_segwit_transaction};
    use coin_btc_fork::btcforkapi::{BtcForkTxInput, Utxo};
    use ikc_common::SignParam;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sign_simple_ltc() {
        //binding device
        bind_test();
        let utxo = Utxo {
            tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
            vout: 0,
            amount: 1000000,
            address: "myxdgXjCRgAskD2g1b6WJttJbuv67hq6sQ".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        };
        let mut unspents = Vec::new();
        unspents.push(utxo);

        let tx_input = BtcForkTxInput {
            to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
            amount: 500000,
            unspents,
            fee: 100000,
            change_address_index: 1u32,
            change_address: "".to_string(),
            seg_wit: "NONE".to_string(),
        };

        let sign_param = SignParam {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/".to_string(),
            network: "TESTNET".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let message = sign_legacy_transaction(&tx_input, &sign_param);
        assert_eq!("0ac4033031303030303030303135383834653564623964653231383233383637313537323334306232303765653835623632383037346537653436373039366332363732363662616637376134303030303030303036623438333034353032323130306237336563616535363861313662313763353536643836616661623465373131333138343866303265383838343339613937386362396331623332646639353730323230316134643633623336636335613632333131343434336136666539643365653864633935363131343838663439626364666263623839646639633839646433623031323130323839636134313638306564626335353934656536333738656264393337653432636436623462393639653430646438326332306566326138616135626164376266666666666666663032323061313037303030303030303030303139373661393134373832316330613337363861613964316133376531366366373630303261656635333733663161383838616338303161303630303030303030303030313937366139313463656538656334643364343362666539313530653065363663373831626631643834653661643332383861633030303030303030124064646139643936653535626365383963616161303461666665626138366432353561636432626165323330343066663532356231616137323237636336633264", hex::encode(message.unwrap()));
    }

    #[test]
    fn test_sign_segwit_ltc() {
        //binding device
        bind_test();
        let unspents = vec![Utxo {
            tx_hash: "e868b66e75376add2154acb558cf45ff7b723f255e2aca794da1548eb945ba8b".to_string(),
            vout: 1,
            amount: 19850000,
            address: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            script_pub_key: "76a914ca4d8acded69ce4f05d0925946d261f86c675fd888ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        }];
        let tx_input = BtcForkTxInput {
            to: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
            amount: 19800000,
            unspents,
            fee: 50000,
            change_address_index: 1u32,
            change_address: "".to_string(),
            seg_wit: "P2WPKH".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "LITECOIN".to_string(),
            path: "m/44'/2'/0'/".to_string(),
            network: "MAINNET".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let message = sign_segwit_transaction(&tx_input, &sign_param);
        assert_eq!("0ab003303230303030303030303031303138626261343562393865353461313464373963613261356532353366373237626666343563663538623561633534323164643661333737353665623636386538303130303030303031373136303031346361346438616364656436396365346630356430393235393436643236316638366336373566643866666666666666663031633031663265303130303030303030303137613931343030616666323166323462633038616635386534316534313836643834393261313062383466396538373032343833303435303232313030643131623366353935396664653161346365306663333762633432336430393732333338663565313136393939663162636266306336616336616139643365613032323031653232336236313135663133633439636339303263366337393463373163343361623561636431616461353930393331356637613332316565303636373137303132313032383963613431363830656462633535393465653633373865626439333765343263643662346239363965343064643832633230656632613861613562616437623030303030303030124035323536386336386135333165363862383962653233653536633661303035366537663533373632373266613233363639386633333139396662306533313566", hex::encode(message.unwrap()));
    }
}
