use crate::transaction::{EosMessageInput, EosMessageOutput, EosTxInput, EosTxOutput, SigData};
use base58::ToBase58;
use tcx_keystore::{
    ChainSigner, Keystore, MessageSigner, Result, TransactionSigner as TraitTransactionSigner,
};

use tcx_crypto::{hash, hex};

fn serial_eos_sig(sig: &[u8]) -> String {
    let to_hash = [sig, "K1".as_bytes()].concat();
    let hashed = hash::ripemd160(&to_hash);
    let data = [sig, &hashed[0..4]].concat();
    format!("SIG_K1_{}", data.to_base58())
}

impl TraitTransactionSigner<EosTxInput, EosTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &EosTxInput,
    ) -> Result<EosTxOutput> {
        let chain_id_bytes = hex::hex_to_bytes(&tx.chain_id)?;
        let zero_padding = [0u8; 32];
        let mut eos_sigs = vec![];
        for tx_hex in &tx.tx_hexs {
            let tx_bytes = hex::hex_to_bytes(&tx_hex)?;
            let tx_hash = hash::sha256(&tx_bytes);
            let tx_with_chain_id = [
                chain_id_bytes.as_slice(),
                tx_bytes.as_slice(),
                &zero_padding,
            ]
            .concat();
            let hashed_tx = hash::sha256(&tx_with_chain_id);
            let sign_result =
                self.sign_recoverable_hash(hashed_tx.as_slice(), symbol, address, None)?;
            // EOS need v r s
            let eos_sig = [sign_result[64..].to_vec(), sign_result[..64].to_vec()].concat();
            eos_sigs.push(SigData {
                signature: serial_eos_sig(&eos_sig),
                hash: hex::bytes_to_hex(&tx_hash),
            });
        }
        Ok(EosTxOutput { sig_data: eos_sigs })
    }
}

impl MessageSigner<EosMessageInput, EosMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        symbol: &str,
        address: &str,
        message: &EosMessageInput,
    ) -> Result<EosMessageOutput> {
        let data_hashed = if message.data.starts_with("0x") {
            hex::hex_to_bytes(&message.data)?
        } else {
            let bytes = message.data.as_bytes();
            hash::sha256(bytes)
        };

        let sign_result =
            self.sign_recoverable_hash(data_hashed.as_slice(), symbol, address, None)?;
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
