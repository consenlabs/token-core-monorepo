use crate::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};
use tcx_keystore::{
    Keystore, MessageSigner as TraitMessageSigner, Result, SignatureParameters, Signer,
    TransactionSigner as TraitTransactionSigner,
};

use bitcoin_hashes::sha256::Hash;
use bitcoin_hashes::Hash as TraitHash;

use anyhow::anyhow;
use tcx_common::{keccak256, FromHex, ToHex};

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
            self.secp256k1_ecdsa_sign_recoverable(&hash[..], &sign_context.derivation_path)?;

        Ok(TronTxOutput {
            signatures: vec![sign_result.to_hex()],
        })
    }
}

impl TraitMessageSigner<TronMessageInput, TronMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        sign_context: &SignatureParameters,
        message: &TronMessageInput,
    ) -> Result<TronMessageOutput> {
        let data = if message.value.to_lowercase().starts_with("0x") {
            Vec::from_hex_auto(&message.value)?
        } else {
            message.value.as_bytes().to_vec()
        };

        let header = match message.header.to_uppercase().as_str() {
            "TRON" => match message.version {
                2 => "\x19TRON Signed Message:\n".as_bytes(),
                _ => "\x19TRON Signed Message:\n32".as_bytes(),
            },
            "ETH" => "\x19Ethereum Signed Message:\n32".as_bytes(),
            "NONE" => "\x19Ethereum Signed Message:\n32".as_bytes(),
            _ => return Err(anyhow!("sign_message_header_type_incorrect")),
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
    use tcx_primitive::Secp256k1PrivateKey;

    #[test]
    fn test_sign_transaction() -> core::result::Result<(), anyhow::Error> {
        let tx = TronTxInput {
            raw_data: "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470a0bfbfa7c92d".to_string()
        };

        let meta = Metadata::default();
        let mut keystore =
            Keystore::Hd(HdKeystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, meta).unwrap());
        let mut guard = KeystoreGuard::unlock_by_password(&mut keystore, TEST_PASSWORD).unwrap();
        let ks = guard.keystore_mut();

        let sign_context = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/145'/0'/0/0".to_string(),
            chain_type: "TRON".to_string(),
            ..Default::default()
        };
        let signed_tx: TronTxOutput = ks.sign_transaction(&sign_context, &tx)?;

        assert_eq!(signed_tx.signatures[0], "beac4045c3ea5136b541a3d5ec2a3e5836d94f28a1371440a01258808612bc161b5417e6f5a342451303cda840f7e21bfaba1011fad5f63538cb8cc132a9768800");

        Ok(())
    }

    #[test]
    fn test_sign_message_by_hd() {
        let coin_info = coin_info_from_param("TRON", "", "", "").unwrap();
        let mut keystore =
            Keystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(&TEST_PASSWORD).unwrap();

        let params = SignatureParameters {
            chain_type: "TRON".to_string(),
            derivation_path: coin_info.derivation_path.to_owned(),
            curve: CurveType::SECP256k1,
            ..Default::default()
        };

        let message = TronMessageInput {
            value: format!("0x{}", "hello world".as_bytes().to_hex()),
            header: "TRON".to_string(),
            version: 1,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0x8686cc3cf49e772d96d3a8147a59eb3df2659c172775f3611648bfbe7e3c48c11859b873d9d2185567a4f64a14fa38ce78dc385a7364af55109c5b6426e4c0f61b");

        let message = TronMessageInput {
            value: format!("0x{}", "hello world".as_bytes().to_hex()),
            header: "NONE".to_string(),
            version: 1,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0xe14f6aab4b87af398917c8a0fd6d065029df9ecc01afbc4d789eefd6c2de1e243272d630992b470c2bbb7f52024280af9bbd2e62d96ecab333c91f527b059ffe1c");

        let message = TronMessageInput {
            value: format!("0x{}", "hello world".as_bytes().to_hex()),
            header: "ETH".to_string(),
            version: 1,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0xe14f6aab4b87af398917c8a0fd6d065029df9ecc01afbc4d789eefd6c2de1e243272d630992b470c2bbb7f52024280af9bbd2e62d96ecab333c91f527b059ffe1c");

        let message = TronMessageInput {
            value: format!("0x{}", "hello world".as_bytes().to_hex()),
            header: "TRON".to_string(),
            version: 2,
        };

        let signed = keystore.sign_message(&params, &message).unwrap();

        assert_eq!(signed.signature, "0xbca12bfcc9f0e23ff1d3567c4ef04ff83ac93346d6b3062d56922cc15b7669436c1aaa6a3f1ec4013545ba7d3bb79ab4b1125159d251a910f92ea198cbc469a21c");

        let message = TronMessageInput {
            value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76".to_string(),
            header: "TRON".to_string(),
            version: 1,
        };
        let signed = keystore.sign_message(&params, &message).unwrap();
        assert_eq!("0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b", signed.signature);

        let message = TronMessageInput {
            value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76".to_string(),
            header: "ETH".to_string(),
            version: 1,
        };
        let signed = keystore.sign_message(&params, &message).unwrap();
        assert_eq!("0x06ff3c5f98b8e8e257f47a66ce8e953c7a7d0f96eb6687da6a98b66a36c2a725759cab3df94d014bd17760328adf860649303c68c4fa6644d9f307e2f32cc3311c", &signed.signature);

        let message = TronMessageInput {
            value: "hello world".to_string(),
            header: "TRON".to_string(),
            version: 1,
        };
        let signed = keystore.sign_message(&params, &message).unwrap();
        assert_eq!("0x06ff3c5f98b8e8e257f47a66ce8e953c7a7d0f96eb6687da6a98b66a36c2a725759cab3df94d014bd17760328adf860649303c68c4fa6644d9f307e2f32cc3311c", &signed.signature);
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
