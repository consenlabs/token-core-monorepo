use crate::transaction::{EosMessageInput, EosMessageOutput, EosTxInput, EosTxOutput, SigData};
use tcx_keystore::{
    Keystore, MessageSigner, Result, SignatureParameters, Signer, TransactionSigner,
};

use bitcoin::util::base58;
use tcx_common::{ripemd160, sha256, FromHex, ToHex};

fn serial_eos_sig(sig: &[u8]) -> String {
    let to_hash = [sig, "K1".as_bytes()].concat();
    let hashed = ripemd160(&to_hash);
    let data = [sig, &hashed[0..4]].concat();
    format!("SIG_K1_{}", base58::encode_slice(&data))
}

impl TransactionSigner<EosTxInput, EosTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &EosTxInput,
    ) -> Result<EosTxOutput> {
        let chain_id_bytes = Vec::from_hex_auto(&tx.chain_id)?;
        let zero_padding = [0u8; 32];
        let mut eos_sigs = vec![];
        for tx_hex in &tx.tx_hexs {
            let tx_bytes = Vec::from_hex_auto(&tx_hex)?;
            let tx_hash = sha256(&tx_bytes);
            let tx_with_chain_id = [
                chain_id_bytes.as_slice(),
                tx_bytes.as_slice(),
                &zero_padding,
            ]
            .concat();
            let hashed_tx = sha256(&tx_with_chain_id);
            let sign_result = self
                .secp256k1_ecdsa_sign_recoverable(hashed_tx.as_slice(), &params.derivation_path)?;
            // EOS need v r s
            let eos_sig = [sign_result[64..].to_vec(), sign_result[..64].to_vec()].concat();
            eos_sigs.push(SigData {
                signature: serial_eos_sig(&eos_sig),
                hash: tx_hash.to_0x_hex(),
            });
        }
        Ok(EosTxOutput { sig_data: eos_sigs })
    }
}

impl MessageSigner<EosMessageInput, EosMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        params: &SignatureParameters,
        message: &EosMessageInput,
    ) -> Result<EosMessageOutput> {
        let data_hashed = if message.data.starts_with("0x") {
            Vec::from_hex_auto(&message.data)?
        } else {
            let bytes = message.data.as_bytes();
            sha256(bytes).to_vec()
        };

        let sign_result =
            self.secp256k1_ecdsa_sign_recoverable(data_hashed.as_slice(), &params.derivation_path)?;
        // EOS need v r s
        let eos_sig = [sign_result[64..].to_vec(), sign_result[..64].to_vec()].concat();
        Ok(EosMessageOutput {
            signature: serial_eos_sig(&eos_sig),
        })
    }
}

// TODO: sign eos using RFC 6979 need new testcase
// #[cfg(test)]
// mod tests {

// }
