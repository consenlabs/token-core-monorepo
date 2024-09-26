use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use num_bigint::BigUint;
use tonlib_core::cell::{BagOfCells, CellBuilder};
use tonlib_core::message::{
    CommonMsgInfo, HasOpcode, JettonTransferMessage, TonMessage, TransferMessage,
};
use tonlib_core::mnemonic::KeyPair;
use tonlib_core::wallet::{TonWallet, WalletVersion};

use tcx_common::{FromHex, ToHex};
use tcx_constants::Result;
use tcx_keystore::{
    Keystore, SignatureParameters, Signer, TransactionSigner as TraitTransactionSigner,
};

use crate::transaction::{TonTxIn, TonTxOut};

impl TraitTransactionSigner<TonTxIn, TonTxOut> for Keystore {
    fn sign_transaction(&mut self, params: &SignatureParameters, tx: &TonTxIn) -> Result<TonTxOut> {
        // construct a null key_pair
        let null_key_pair = KeyPair {
            public_key: vec![],
            secret_key: vec![],
        };

        let wallet = TonWallet::derive_default(WalletVersion::V4R2, &null_key_pair)?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as u32;
        let transfer = if tx.is_jetton {
            let jetton_amount = BigUint::from_str(&tx.jetton_amount)?;
            let from = tx.from.parse()?;
            let to = tx.to.parse()?;
            let amount = BigUint::from_str(&tx.amount)?;
            let mut jetton_transfer = JettonTransferMessage::new(&to, &jetton_amount);
            jetton_transfer.with_response_destination(&from);
            jetton_transfer.set_query_id(tx.query_id);
            let cell = jetton_transfer.build()?;

            TransferMessage::new(CommonMsgInfo::new_default_internal(&to, &amount))
                .with_data(Arc::new(cell))
                .build()?

            // let wallet = TonWallet::derive_default(WalletVersion::V4R2, &null_key_pair)?;
            // let now = SystemTime::now()
            //     .duration_since(SystemTime::UNIX_EPOCH)?
            //     .as_secs() as u32;
            // let body = wallet.create_external_body(now + 60, tx.sequence_no.try_into().unwrap(), vec![transfer])?;
            // let hash = body.cell_hash();
            // let sig = self.ed25519_sign(&hash.to_vec(), &params.derivation_path)?;
            // let mut body_builder = CellBuilder::new();
            // body_builder.store_slice(sig.as_slice())?;
            // body_builder.store_cell(&body)?;
            // let signed_body = body_builder.build()?;
            //
            // let wrapped_body = wallet.wrap_signed_body(signed_body, true)?;
            // let boc = BagOfCells::from_root(wrapped_body);
            // let tx = boc.serialize(true)?;
            // let signature = tx.to_hex();
            // Ok(TonTxOut {
            //     signature,
            // })
        } else {
            let to = tx.to.parse()?;
            let amount = BigUint::from_str(&tx.amount)?;
            TransferMessage::new(CommonMsgInfo::new_default_internal(&to, &amount))
                // .with_data(Arc::new(cell))
                .build()?
        };

        let body = wallet.create_external_body(
            now + 60,
            tx.sequence_no.try_into().unwrap(),
            vec![Arc::new(transfer)],
        )?;
        let hash = body.cell_hash();
        let sig = self.ed25519_sign(&hash.to_vec(), &params.derivation_path)?;
        let mut body_builder = CellBuilder::new();
        body_builder.store_slice(sig.as_slice())?;
        body_builder.store_cell(&body)?;
        let signed_body = body_builder.build()?;

        let wrapped_body = wallet.wrap_signed_body(signed_body, true)?;
        let boc = BagOfCells::from_root(wrapped_body);
        let tx = boc.serialize(true)?;
        let signature = tx.to_hex();
        Ok(TonTxOut { signature })
    }
}

#[cfg(test)]
mod test_super {
    use crate::transaction::TonTxIn;
    use tcx_common::ToHex;
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{HdKeystore, Keystore, Metadata, SignatureParameters, TransactionSigner};
    use tonlib_core::wallet::WalletVersion;

    #[test]
    fn test_nacl_sign() {
        let hd =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let path = "m/44'/607'/0'/0'/0'".to_string();
        let coin = CoinInfo {
            coin: "TON".to_string(),
            // todo: the ton path is not official
            derivation_path: "m/44'/607'/0'/0'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
        };

        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "EQCKJfmBlnFiINcL1MoCjuyxULXaOEA-k5iHcr4L18RuhQHo",
            acc.address
        );
        let sec_key = keystore.get_private_key(CurveType::ED25519, &path).unwrap();
        assert_eq!(
            sec_key.to_bytes().to_hex(),
            "34815c96ad2434988d86a01e4b639acf41e8ecac7eeb260635b8a47028bbefd3"
        );

        let tx_in = TonTxIn {
            from: "EQCKJfmBlnFiINcL1MoCjuyxULXaOEA-k5iHcr4L18RuhQHo".to_string(),
            to: "0QBhzrMl_WXpLg6QQDVXAaCJAiCCDczkgmIxCfBejgH4RfFK".to_string(),
            amount: "100000000000".to_string(),
            memo: "".to_string(),
            is_jetton: false,
            jetton_amount: "20000000000".to_string(),
            query_id: 30000,
            sequence_no: 0,
            wallet_version: "".to_string(),
        };

        let param = SignatureParameters {
            curve: CurveType::ED25519,
            derivation_path: path.to_string(),
            chain_type: "TON".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let sign_ret = keystore.sign_transaction(&param, &tx_in).unwrap();
        assert_eq!(sign_ret.signature, "");

        let keypair = tonlib_core::mnemonic::KeyPair {
            public_key: vec![],
            secret_key: sec_key.to_bytes(),
        };

        let wallet =
            tonlib_core::wallet::TonWallet::derive_default(WalletVersion::V4R2, &keypair).unwrap();

        //
        //
        //
        // let pk = keystore.get_private_key(CurveType::ED25519, "m/44'/607'/0'/0/0").unwrap();
        //

        // let keystore = Keystore::
    }
}
