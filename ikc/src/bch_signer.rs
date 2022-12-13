use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;

use coin_bch::transaction::{BchTransaction, Utxo};
use coin_btc_fork::btcforkapi::{BtcForkTxInput, BtcForkTxOutput};
use ikc_common::utility::hex_to_bytes;
use ikc_common::SignParam;
use prost::Message;

pub fn sign_transaction(data: &[u8], sign_param: &SignParam) -> Result<Vec<u8>> {
    let input: BtcForkTxInput = BtcForkTxInput::decode(data).expect("BtcTxInput");
    sign_bch_transaction(&input, sign_param)
}

pub fn sign_bch_transaction(param: &BtcForkTxInput, sign_param: &SignParam) -> Result<Vec<u8>> {
    let mut unspents = Vec::new();
    for utxo in &param.unspents {
        let new_utxo = Utxo {
            txhash: utxo.tx_hash.to_string(),
            vout: utxo.vout,
            amount: utxo.amount,
            address: utxo.address.to_string(),
            script_pubkey: utxo.script_pub_key.to_string(),
            derive_path: utxo.derived_path.to_string(),
            sequence: utxo.sequence,
        };
        unspents.push(new_utxo);
    }

    let bch_tx = BchTransaction {
        to: param.to.to_string(),
        amount: param.amount,
        unspents: unspents,
        fee: param.fee,
    };

    let network = if sign_param.network == "TESTNET".to_string() {
        Network::Testnet
    } else {
        Network::Bitcoin
    };

    let extra_data = vec![];

    let signed = bch_tx.sign_transaction(
        network,
        &sign_param.path,
        param.change_address_index as i32,
        &param.change_address,
        &extra_data,
    )?;
    let tx_sign_result = BtcForkTxOutput {
        signature: signed.signature,
        tx_hash: signed.tx_hash,
        wtx_hash: "".to_string(),
    };
    encode_message(tx_sign_result)
}

#[cfg(test)]
mod tests {
    use crate::bch_signer::sign_bch_transaction;
    use coin_bch::transaction::BchTransaction;
    use coin_btc_fork::btcforkapi::{BtcForkTxInput, BtcForkTxOutput, Utxo};
    use ikc_common::SignParam;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_bch_sign() {
        bind_test();

        let utxo = Utxo {
            tx_hash: "09c3a49c1d01f6341c43ea43dd0de571664a45b4e7d9211945cb3046006a98e2".to_string(),
            vout: 0,
            amount: 100000,
            address: "qzld7dav7d2sfjdl6x9snkvf6raj8lfxjcj5fa8y2r".to_string(),
            script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
            derived_path: "0/0".to_string(),
            sequence: 0,
        };
        let mut utxos = Vec::new();
        utxos.push(utxo);
        let txInput = BtcForkTxInput {
            to: "qq40fskqshxem2gvz0xkf34ww3h6zwv4dcr7pm0z6s".to_string(),
            amount: 93454,
            fee: 6000,
            change_address_index: 0,
            change_address: "qq5jyy9vmsznss93gmt8m2v2fep7wvpdwsn2hrjgsg".to_string(),
            unspents: utxos,
            seg_wit: "".to_string(),
        };

        let sign_param = SignParam {
            chain_type: "".to_string(),
            path: "m/44'/145'/0'/".to_string(),
            network: "MAINET".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
        };

        let message = sign_bch_transaction(&txInput, &sign_param);
        assert_eq!("0ac4033031303030303030303165323938366130303436333063623435313932316439653762343435346136363731653530646464343365613433316333346636303131643963613463333039303030303030303036623438333034353032323130306164633130333634346361353432666261333431323662636165663237613934616633346432373232336265376461646436333462386664613239633337366530323230303562323333633037633234633838363062626338393936323461353566386537633666656232353062616364633462623062666664353666666138303037633431323130323531343932646662323939663231653432363330373138306235373766393237363936623664663062363138383332313566383865623936383564336434343966666666666666663032306536643031303030303030303030303139373661393134326166346332633038356364396461393063313363643634633661653734366661313339393536653838616332323032303030303030303030303030313937366139313432393232313061636463303533383430623134366436376461393861346534336537333032643734383861633030303030303030124037363663636331363035323563303762613563393533646664343233373331366264316462386436333561636366323266346366383737343363306631306135", hex::encode(message.unwrap()));
    }
}
