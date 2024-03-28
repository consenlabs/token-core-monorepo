use std::vec;

use crate::transaction::{EosMessageInput, EosMessageOutput, EosTxInput, EosTxOutput, SigData};
use tcx_keystore::{
    tcx_ensure, Keystore, MessageSigner, Result, SignatureParameters, Signer, TransactionSigner,
};

use anyhow::anyhow;
use bitcoin::util::base58;
use tcx_common::{ripemd160, sha256, FromHex, ToHex};

fn serial_eos_sig(sig: &[u8]) -> String {
    let to_hash = [sig, "K1".as_bytes()].concat();
    let hashed = ripemd160(&to_hash);
    let data = [sig, &hashed[0..4]].concat();
    format!("SIG_K1_{}", base58::encode_slice(&data))
}

fn is_canonical(sig: &[u8]) -> bool {
    !(sig[0] & 0x80 != 0)
        && !(sig[0] == 0 && !(sig[1] & 0x80 != 0))
        && !(sig[32] & 0x80 != 0)
        && !(sig[32] == 0 && !(sig[33] & 0x80 != 0))
}

fn i32_to_u8_array(value: i32) -> [u8; 32] {
    let bytes = value.to_be_bytes();
    let mut result = [0u8; 32];
    result[..4].copy_from_slice(&bytes);
    result
}

fn eos_sign(keystore: &mut Keystore, hashed: &[u8], path: &str) -> Result<String> {
    let mut sign_result: Vec<u8> = vec![];
    let mut is_canon = false;
    for nonce in 0..1000 {
        sign_result = keystore.secp256k1_ecdsa_sign_recoverable_with_noncedata(
            hashed,
            &path,
            &i32_to_u8_array(nonce),
        )?;
        if is_canonical(&sign_result) {
            is_canon = true;
            break;
        }
    }
    tcx_ensure!(is_canon, anyhow!("cannot generate a eos canon sig"));
    sign_result[64] += 27 + 4;
    let sig = [sign_result[64..].to_vec(), sign_result[..64].to_vec()].concat();
    Ok(serial_eos_sig(&sig))
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
            let tx_bytes = Vec::from_hex_auto(tx_hex)?;
            let tx_hash = sha256(&tx_bytes);
            let tx_with_chain_id = [
                chain_id_bytes.as_slice(),
                tx_bytes.as_slice(),
                &zero_padding,
            ]
            .concat();
            let hashed_tx = sha256(&tx_with_chain_id);
            let eos_sig = eos_sign(self, &hashed_tx, &params.derivation_path)?;
            // EOS need v r s

            eos_sigs.push(SigData {
                signature: eos_sig,
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

        tcx_ensure!(
            data_hashed.len() == 32,
            anyhow!("{}", "hashed data must be 32 bytes")
        );

        let eos_sig = eos_sign(self, &data_hashed, &params.derivation_path)?;
        Ok(EosMessageOutput { signature: eos_sig })
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use bitcoin::hashes::hex::ToHex;
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{
        HdKeystore, Keystore, MessageSigner, Metadata, PrivateKeystore, SignatureParameters,
        TransactionSigner,
    };
    use tcx_primitive::{PrivateKey, Secp256k1PrivateKey};

    use crate::transaction::{EosMessageInput, EosTxInput};

    #[test]
    fn test_eos_sign_tx() {
        let meta = Metadata::default();

        let hd_keystore = HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, meta).unwrap();
        let mut keystore = Keystore::Hd(hd_keystore);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let sign_param = SignatureParameters {
            chain_type: "EOS".to_string(),
            derivation_path: "m/44'/194'/0'/0/0".to_string(),
            ..SignatureParameters::default()
        };
        let tx_input = EosTxInput {
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            tx_hexs: vec!["2b03b26547b625edc1c6000000000100a6823403ea3055000000572d3ccdcd0130069b34b2a9a48b00000000a8ed32322130069b34b2a9a48b10425e79aa47b374640000000000000004454f53000000000000".to_string(),
            "8c05b2650abbf70ba628000000000100a6823403ea3055000000572d3ccdcd0130069b34b2a9a48b00000000a8ed32322130069b34b2a9a48b10425e79aa47b374e80300000000000004454f53000000000000".to_string(),
            "5a09b265a5c205ed6bea000000000100a6823403ea3055000000572d3ccdcd0110425e79aa47b37400000000a8ed32322110425e79aa47b37430069b34b2a9a48b640000000000000004454f53000000000000".to_string(),
            "db0bb265a7c74d49719c000000000100a6823403ea3055000000572d3ccdcd0110425e79aa47b37400000000a8ed32322110425e79aa47b37430069b34b2a9a48be80300000000000004454f53000000000000".to_string(),
            "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string()]

        };
        let ret = keystore.sign_transaction(&sign_param, &tx_input).unwrap();
        assert_eq!(ret.sig_data[0].signature, "SIG_K1_KYgqnbZkL57TAJtgZ4ntrCxQ38B313WWpZEDyGwA7s4sjmyHissY6WAeCdyYHukBWp2QsqEH8hdtQLchR2LZSzMhvvHmCm");
        assert_eq!(
            ret.sig_data[0].hash,
            "0x0461387aa99644399b1c8c876805fc775f96e6a00ce18ffbe4eaa930ad6e7af8"
        );
        assert_eq!(ret.sig_data[1].signature, "SIG_K1_Jy7PBEwCpvvf5k4yzrqq1KeBCZi5qru7mp3CspNw8n8xENpN8Ar6s3ckuEeH66Rd9QFbUZzrD4pAemkBEWMyBM7PBdDR4t");
        assert_eq!(
            ret.sig_data[1].hash,
            "0xe36d9a49ca7768198a092c5b3f9b9766343ff14eb1fde851bed9cbda2ef1ab58"
        );
        assert_eq!(ret.sig_data[2].signature, "SIG_K1_K1iY4LUoLwnYVFMaWZddr74NSmLcCBDEysybA7oTLMn7dYtFdeHpy8oSv4rEdGYoa8rzsE17QaPJikSyjDY4t3EeK2m1ir");
        assert_eq!(ret.sig_data[3].signature, "SIG_K1_Ki7M5TB9Di3i2orD1ntym5xmhh5rAeJPK8XxNfAUjeNc3SQyMA9UZ37ptfTLjngb9cfhdBG3j2DQXrderrXH59t5DcHwgT");
        assert_eq!(ret.sig_data[4].signature, "SIG_K1_K7EUD2iuUi4QFgTNuondGqjaWJ4AWzp1EMhqKg4t1oGoSKhjvTpfqv6EcD6M2R8qQvJjf7f2mV8zHEXHgLKH985DU1JPyf");
    }

    #[test]
    fn test_pk_store_eos_sign_msg() {
        let meta = Metadata::default();

        let hex_sec_key =
            Secp256k1PrivateKey::from_wif("5KAigHMamRhN7uwHFnk3yz7vUTyQT1nmXoAA899XpZKJpkqsPFp")
                .unwrap()
                .to_bytes()
                .to_hex();
        let pk_keystore = PrivateKeystore::from_private_key(
            &hex_sec_key,
            TEST_PASSWORD,
            tcx_constants::CurveType::SECP256k1,
            meta,
            None,
        )
        .unwrap();
        let mut keystore = Keystore::PrivateKey(pk_keystore);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let sign_param = SignatureParameters {
            chain_type: "EOS".to_string(),
            ..SignatureParameters::default()
        };
        let tx_input = EosTxInput {
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            tx_hexs: vec!["2b03b26547b625edc1c6000000000100a6823403ea3055000000572d3ccdcd0130069b34b2a9a48b00000000a8ed32322130069b34b2a9a48b10425e79aa47b374640000000000000004454f53000000000000".to_string(),
            "8c05b2650abbf70ba628000000000100a6823403ea3055000000572d3ccdcd0130069b34b2a9a48b00000000a8ed32322130069b34b2a9a48b10425e79aa47b374e80300000000000004454f53000000000000".to_string(),
            "5a09b265a5c205ed6bea000000000100a6823403ea3055000000572d3ccdcd0110425e79aa47b37400000000a8ed32322110425e79aa47b37430069b34b2a9a48b640000000000000004454f53000000000000".to_string(),
            "db0bb265a7c74d49719c000000000100a6823403ea3055000000572d3ccdcd0110425e79aa47b37400000000a8ed32322110425e79aa47b37430069b34b2a9a48be80300000000000004454f53000000000000".to_string(),
            "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string()]

        };
        let ret = keystore.sign_transaction(&sign_param, &tx_input).unwrap();
        assert_eq!(ret.sig_data[0].signature, "SIG_K1_KYgqnbZkL57TAJtgZ4ntrCxQ38B313WWpZEDyGwA7s4sjmyHissY6WAeCdyYHukBWp2QsqEH8hdtQLchR2LZSzMhvvHmCm");
        assert_eq!(
            ret.sig_data[0].hash,
            "0x0461387aa99644399b1c8c876805fc775f96e6a00ce18ffbe4eaa930ad6e7af8"
        );
        assert_eq!(ret.sig_data[1].signature, "SIG_K1_Jy7PBEwCpvvf5k4yzrqq1KeBCZi5qru7mp3CspNw8n8xENpN8Ar6s3ckuEeH66Rd9QFbUZzrD4pAemkBEWMyBM7PBdDR4t");
        assert_eq!(
            ret.sig_data[1].hash,
            "0xe36d9a49ca7768198a092c5b3f9b9766343ff14eb1fde851bed9cbda2ef1ab58"
        );
        assert_eq!(ret.sig_data[2].signature, "SIG_K1_K1iY4LUoLwnYVFMaWZddr74NSmLcCBDEysybA7oTLMn7dYtFdeHpy8oSv4rEdGYoa8rzsE17QaPJikSyjDY4t3EeK2m1ir");
        assert_eq!(ret.sig_data[3].signature, "SIG_K1_Ki7M5TB9Di3i2orD1ntym5xmhh5rAeJPK8XxNfAUjeNc3SQyMA9UZ37ptfTLjngb9cfhdBG3j2DQXrderrXH59t5DcHwgT");
        assert_eq!(ret.sig_data[4].signature, "SIG_K1_K7EUD2iuUi4QFgTNuondGqjaWJ4AWzp1EMhqKg4t1oGoSKhjvTpfqv6EcD6M2R8qQvJjf7f2mV8zHEXHgLKH985DU1JPyf");
    }

    #[test]
    fn test_eos_sign_msg() {
        let meta = Metadata::default();

        let hex_sec_key =
            Secp256k1PrivateKey::from_wif("5HxQKWDznancXZXm7Gr2guadK7BhK9Zs8ejDhfA9oEBM89ZaAru")
                .unwrap()
                .to_bytes()
                .to_hex();
        let pk_keystore = PrivateKeystore::from_private_key(
            &hex_sec_key,
            TEST_PASSWORD,
            tcx_constants::CurveType::SECP256k1,
            meta,
            None,
        )
        .unwrap();
        let mut keystore = Keystore::PrivateKey(pk_keystore);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let sign_param = SignatureParameters {
            chain_type: "EOS".to_string(),
            ..SignatureParameters::default()
        };
        let tx_input = EosMessageInput {
            data: "0x6cb75bc5a46a7fdb64b92efefca01ed7b060ab5e0d625226e8efbc0980c3ddc1".to_string(),
        };
        let ret = keystore.sign_message(&sign_param, &tx_input).unwrap();
        assert_eq!(ret.signature, "SIG_K1_KkkPJXMxGUUeS6b5FmKrXE448N1Gc4x87j4JLVuENuba5QRUmFczGe9EmzeoCajRH5YLGEGcYjWSXxxfR5b6RTCoNUdCVy");
    }
}
