use crate::transaction::{TezosRawTxIn, TezosTxOut};
use anyhow::anyhow;
use bitcoin::util::base58;
use blake2b_simd::Params;
use tcx_common::{FromHex, ToHex};
use tcx_constants::Result;
use tcx_keystore::{
    Keystore, SignatureParameters, Signer, TransactionSigner as TraitTransactionSigner,
};

impl TraitTransactionSigner<TezosRawTxIn, TezosTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &TezosRawTxIn,
    ) -> Result<TezosTxOut> {
        if !params.derivation_path.is_empty() {
            let path_parts = params.derivation_path.split('/').collect::<Vec<_>>();
            if path_parts.len() < 4 || path_parts[2] != "1729'" {
                return Err(anyhow!("invalid_sign_path"));
            }
        }

        let raw_data_bytes = if tx.raw_data.starts_with("0x") {
            tx.raw_data[2..].to_string()
        } else {
            tx.raw_data.clone()
        };

        //Blake2b hash
        let mut blake2b_params = Params::new();
        blake2b_params.hash_length(32);
        //add watermark https://gitlab.com/tezos/tezos/-/issues/199
        // https://tezos.gitlab.io/user/key-management.html#signer-requests
        let mut hash_message: Vec<u8> = vec![0x03];
        hash_message.extend(Vec::from_hex(raw_data_bytes)?.as_slice());
        let hash_result = blake2b_params.hash(hash_message.as_slice());
        let sign_result = self.sign_hash(
            hash_result.as_bytes(),
            &params.derivation_path,
            "ed25519",
            "",
        )?;

        //tezos ed25519 signature prefix
        let edsig_prefix: [u8; 5] = [9, 245, 205, 134, 18];
        let mut edsig_source_data = vec![];
        edsig_source_data.extend(&edsig_prefix);
        edsig_source_data.extend(sign_result.as_slice());

        let sign_result_hex = sign_result.to_hex();
        let tx_out = TezosTxOut {
            signature: sign_result_hex.clone(),
            edsig: base58::check_encode_slice(edsig_source_data.as_slice()),
            sbytes: format!("{}{}", tx.raw_data, sign_result_hex),
        };
        Ok(tx_out)
    }
}
