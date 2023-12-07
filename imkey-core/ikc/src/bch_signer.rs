use crate::error_handling::Result;
use crate::message_handler::encode_message;
use bitcoin::Network;
use coin_bch::transaction::{BchTransaction, Utxo};
use coin_btc_fork::btcforkapi::{BtcForkTxInput, BtcForkTxOutput};
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
    use coin_btc_fork::btcforkapi::{BtcForkTxInput, Utxo};
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
        let tx_input = BtcForkTxInput {
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

        let message = sign_bch_transaction(&tx_input, &sign_param);
        assert_eq!("0afe0230313030303030303031653239383661303034363330636234353139323164396537623434353461363637316535306464643433656134333163333466363031316439636134633330393030303030303030366134373330343430323230363965643765623335353132616337636438393763386631306161656634666231666262656333356661343438653235346263626163646132623631343630393032323030336564653965383465383430386238643431306230613838656465656564383934623033393631623731353061663038626430653231636331313162633037343132313032353134393264666232393966323165343236333037313830623537376639323736393662366466306236313838333231356638386562393638356433643434396666666666666666303130653664303130303030303030303030313937366139313432616634633263303835636439646139306331336364363463366165373436666131333939353665383861633030303030303030124061333938363265343638353138306564366532633231613532643561643138376431346163363766343335616636313134343037663966366335666366383436", hex::encode(message.unwrap()));
    }
}
