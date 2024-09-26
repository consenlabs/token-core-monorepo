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

        let transfer = if tx.is_jetton {
            let jetton_amount = BigUint::from(&tx.jetton_amount);
            let from = tx.from.parse()?;
            let to = tx.to.parse()?;
            let amount = BigUint::from(&tx.amount);
            let mut jetton_transfer =
                JettonTransferMessage::new(&to, &jetton_amount).with_response_destination(&from);
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
            let amount = BigUint::from(&tx.amount);
            TransferMessage::new(CommonMsgInfo::new_default_internal(&to, &amount))
                // .with_data(Arc::new(cell))
                .build()?
        };

        let wallet = TonWallet::derive_default(WalletVersion::V4R2, &null_key_pair)?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as u32;
        let body = wallet.create_external_body(
            now + 60,
            tx.sequence_no.try_into().unwrap(),
            vec![transfer],
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
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_keystore::{HdKeystore, Keystore, Metadata};

    #[test]
    fn test_nacl_sign() {
        let hd = HdKeystore::new("imtokenq", Metadata::default());
        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: "m/44'/607'/0'/0/0".to_string(),
            curve: CurveType::ED25519,
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
        };

        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password("imtokenq").unwrap();
        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!("", acc.address);

        // let tx_in = TonTxIn {
        //     from: "".to_string(),
        //     to: "".to_string(),
        //     amount: "".to_string(),
        //     memo: "".to_string(),
        //     is_jetton: false,
        //     jetton_amount: "".to_string(),
        //     query_id: 0,
        //     sequence_no: 0,
        // }
        //
        //
        //
        // let pk = keystore.get_private_key(CurveType::ED25519, "m/44'/607'/0'/0/0").unwrap();
        //

        // let keystore = Keystore::
    }
}
