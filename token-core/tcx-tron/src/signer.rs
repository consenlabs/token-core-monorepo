use crate::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use tcx_keystore::{
    Keystore, MessageSigner as TraitMessageSigner, Result, SignatureParameters, Signer,
    TransactionSigner as TraitTransactionSigner,
};

use bitcoin_hashes::sha256::Hash;
use bitcoin_hashes::Hash as TraitHash;

use failure::format_err;
use tcx_common::{keccak256, utf8_or_hex_to_bytes, FromHex, ToHex};

// http://jsoneditoronline.org/index.html?id=2b86a8503ba641bebed73f32b4ac9c42
//{
//"visible": false,
//"txID": "88817b9c6276e3c535e4f8f15baf546292ca6ad9d44a7d97857bd6f8909d63d4",
//"raw_data": {
//"contract": [
//{
//"parameter": {
//"value": {
//"amount": 100000,
//"owner_address": "415c68cc82c87446f602f019e5fd797437f5b79cc2",
//"to_address": "4156a6076cd1537fa317c2606e4edfa4acd3e8e92e"
//},
//"type_url": "type.googleapis.com/protocol.TransferContract"
//},
//"type": "TransferContract"
//}
//],
//"ref_block_bytes": "02a2",
//"ref_block_hash": "e216e254e43ee108",
//"expiration": 1571898861000,
//"timestamp": 1571898802704
//},
//"raw_data_hex": "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d",
//"chainId": "1",
//"id": "d5ca6979-2586-4b6f-88f2-09a3d8b833b0",
//"password": "123123123",
//"chainType": "TRON"
//}

impl TraitTransactionSigner<TronTxInput, TronTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        sign_context: &SignatureParameters,
        tx: &TronTxInput,
    ) -> Result<TronTxOutput> {
        let data = Vec::from_hex(&tx.raw_data)?;
        let hash = Hash::hash(&data);

        let sign_result =
            self.secp256k1_ecdsa_sign_recoverable(&hash[..], &sign_context.derivation_path);

        match sign_result {
            Ok(r) => Ok(TronTxOutput {
                signatures: vec![r.to_hex()],
            }),
            Err(_e) => Err(format_err!("{}", "can not format error")),
        }
    }
}

impl TraitMessageSigner<TronMessageInput, TronMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        sign_context: &SignatureParameters,
        message: &TronMessageInput,
    ) -> Result<TronMessageOutput> {
        let data = Vec::from_hex_auto(&message.value)?;

        let header = match message.is_tron_header {
            true => "\x19TRON Signed Message:\n32".as_bytes(),
            false => "\x19Ethereum Signed Message:\n32".as_bytes(),
        };
        let to_hash = [header, &data].concat();

        let hash = keccak256(&to_hash);
        let mut sign_result =
            self.secp256k1_ecdsa_sign_recoverable(&hash[..], &sign_context.derivation_path)?;
        sign_result[64] += 27;
        Ok(TronMessageOutput {
            signature: sign_result.to_0x_hex(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tcx_constants::{coin_info_from_param, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{HdKeystore, Keystore, KeystoreGuard, Metadata};
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};

    #[test]
    fn test_sign_transaction() -> core::result::Result<(), failure::Error> {
        let tx = TronTxInput {
            raw_data: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470a0bfbfa7c92d".to_string()
        };

        let meta = Metadata::default();
        let mut keystore =
            Keystore::Hd(HdKeystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, meta).unwrap());
        let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();
        let ks = guard.keystore_mut();

        let mut sign_context = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/145'/0'/0/0".to_string(),
            chain_type: "TRON".to_string(),
            ..Default::default()
        };
        let signed_tx: TronTxOutput = ks.sign_transaction(&sign_context, &tx)?;

        assert_eq!(signed_tx.signatures[0], "beac4045c3ea5136b541a3d5ec2a3e5836d94f28a1371440a01258808612bc161b5417e6f5a342451303cda840f7e21bfaba1011fad5f63538cb8cc132a9768800");

        sign_context.derivation_path = "".to_string();
        let signed_tx = ks.sign_transaction(&sign_context, &tx);
        assert_eq!(signed_tx.err().unwrap().to_string(), "can not format error");
        Ok(())
    }

    #[test]
    fn test_sign_message_by_hd() {
        let coin_info = coin_info_from_param("TRON", "", "", "").unwrap();
        let mut keystore =
            Keystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(&TEST_PASSWORD).unwrap();

        let mut params = SignatureParameters {
            chain_type: "TRON".to_string(),
            derivation_path: coin_info.derivation_path.to_owned(),
            curve: CurveType::SECP256k1,
            ..Default::default()
        };

        let message = TronMessageInput {
            value: "hello world".as_bytes().to_hex(),
            is_tron_header: true,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0x8686cc3cf49e772d96d3a8147a59eb3df2659c172775f3611648bfbe7e3c48c11859b873d9d2185567a4f64a14fa38ce78dc385a7364af55109c5b6426e4c0f61b");

        let message = TronMessageInput {
            value: "hello world".as_bytes().to_hex(),
            is_tron_header: false,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0xe14f6aab4b87af398917c8a0fd6d065029df9ecc01afbc4d789eefd6c2de1e243272d630992b470c2bbb7f52024280af9bbd2e62d96ecab333c91f527b059ffe1c");
    }

    #[test]
    fn test_sign_message_by_private_key() {
        let sk =
            Secp256k1PrivateKey::from_wif("L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB")
                .unwrap();
        let message =
            Vec::from_hex("645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76")
                .unwrap();
        let header = "\x19TRON Signed Message:\n32".as_bytes();
        let to_signed = [header.to_vec(), message].concat();

        let hash = keccak256(&to_signed);
        let mut signed = sk.sign_recoverable(&hash).unwrap();
        signed[64] = signed[64] + 27;
        assert_eq!("7209610445e867cf2a36ea301bb5d1fbc3da597fd2ce4bb7fa64796fbf0620a4175e9f841cbf60d12c26737797217c0082fdb3caa8e44079e04ec3f93e86bbea1c", signed.to_hex())
    }
}
