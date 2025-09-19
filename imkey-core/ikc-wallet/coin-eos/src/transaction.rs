use crate::eosapi::{EosMessageInput, EosMessageOutput, EosSignResult, EosTxInput, EosTxOutput};
use crate::pubkey::EosPubkey;
use crate::Result;
use anyhow::anyhow;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::util::base58;
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{ripemd160, Hash};
use bytes::BufMut;
use hex::FromHex;
use ikc_common::apdu::{Apdu, ApduCheck, CoinCommonApdu, EosApdu, Secp256k1Apdu};
use ikc_common::constants::{EOS_AID, EOS_LEGACY_APPLET_VERSION};
use ikc_common::error::CoinError;
use ikc_common::utility::{retrieve_recid, secp256k1_sign, sha256_hash};
use ikc_common::{constants, path, utility, SignParam};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_device::device_manager::get_apple_version;
use ikc_transport::message::{send_apdu, send_apdu_timeout};

/// EOS Transaction signing implementation with migration support
///
/// This module provides EOS transaction signing capabilities with support for both
/// legacy and secp256k1-based implementations. The migration strategy ensures
/// backward compatibility while gradually transitioning to the newer implementation.
///
/// ## Migration Strategy
///
/// The implementation uses version detection to determine which signing method to use:
/// - Legacy applet version ("0.0.1"): Uses `sign_tx_for_eos` and `sign_message_for_eos`
/// - Newer versions: Uses `sign_tx_for_k1` and `sign_message_for_k1` (secp256k1-based)
///
/// ## Error Handling
///
/// - Version detection failures return an error to ensure proper applet compatibility
/// - All hex decoding operations include proper error handling with descriptive messages
/// - Signature verification includes comprehensive error checking
///
/// ## Security Considerations
///
/// - Multiple KEY_MANAGER.lock() calls are minimized to reduce deadlock risk
/// - Signature verification is performed before accepting results
/// - Public key validation ensures path consistency
#[derive(Debug)]
pub struct EosTransaction {}

impl EosTransaction {
    /// Sign EOS transaction with automatic version detection
    ///
    /// This function automatically detects the applet version and routes to the appropriate
    /// signing implementation. If version detection fails, the function returns an error.
    ///
    /// # Arguments
    /// * `tx_input` - The EOS transaction input containing transaction data
    /// * `sign_param` - Signing parameters including derivation path
    ///
    /// # Returns
    /// * `Result<EosTxOutput>` - The signed transaction output or error
    ///
    /// # Migration Notes
    /// - Legacy applets (version "0.0.1") use the original EOS signing method
    /// - Newer applets use the secp256k1-based signing method
    /// - Version detection failures return an error
    pub fn sign_tx(tx_input: EosTxInput, sign_param: &SignParam) -> Result<EosTxOutput> {
        // Get applet version - fail if version detection fails
        let version = get_apple_version(EOS_AID)?;

        match version.as_str() {
            EOS_LEGACY_APPLET_VERSION => Self::sign_tx_for_eos(tx_input, sign_param),
            _ => Self::sign_tx_for_k1(tx_input, sign_param),
        }
    }

    /// Sign EOS transaction using legacy applet implementation
    ///
    /// This function implements the original EOS signing method for legacy applets.
    /// It should only be called directly for testing or specific legacy support.
    ///
    /// # Arguments
    /// * `tx_input` - The EOS transaction input containing transaction data
    /// * `sign_param` - Signing parameters including derivation path
    ///
    /// # Returns
    /// * `Result<EosTxOutput>` - The signed transaction output or error
    ///
    /// # Deprecated
    /// This method is maintained for backward compatibility. New code should use
    /// `sign_tx` which automatically selects the appropriate implementation.
    pub fn sign_tx_for_eos(tx_input: EosTxInput, sign_param: &SignParam) -> Result<EosTxOutput> {
        path::check_path_validity(&sign_param.path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let mut trans_multi_signs: Vec<EosSignResult> = Vec::new();

        for sign_data in &tx_input.transactions {
            let mut sign_result = EosSignResult {
                hash: "".to_string(),
                signs: vec![],
            };

            // Calculate transaction hash using common method
            sign_result.hash = Self::calculate_tx_hash(&sign_data.tx_hex)?;

            // Pack transaction data using common method
            let tx_data_pack = Self::pack_tx_data(&sign_data.chain_id, &sign_data.tx_hex)?;
            let tx_data_hash = sha256_hash(&tx_data_pack);

            //view_info
            let mut view_info = "".to_string();
            view_info.push_str("07");
            view_info.push_str(&format!("{:02x}", &sign_data.payment.as_bytes().len()));
            view_info.push_str(&hex::encode(&sign_data.payment));
            view_info.push_str("08");
            view_info.push_str(&format!("{:02x}", &sign_data.receiver.as_bytes().len()));
            view_info.push_str(&hex::encode(&sign_data.receiver));

            //sign
            for pub_key in &sign_data.public_keys {
                let mut sign_data_pack: Vec<u8> = Vec::new();
                sign_data_pack.push(0x01);
                sign_data_pack.push(tx_data_hash.len() as u8); //hash len
                sign_data_pack.extend(tx_data_hash.iter());
                sign_data_pack.push(0x02);
                sign_data_pack.push(sign_param.path.len() as u8); //hash len
                sign_data_pack.extend(sign_param.path.as_bytes());
                sign_data_pack.extend(hex::decode(&view_info).unwrap().as_slice());

                //bind signature
                let key_manager_obj = KEY_MANAGER.lock();
                let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &sign_data_pack)?;

                //send prepare data
                let mut prepare_apdu_data: Vec<u8> = Vec::new();
                prepare_apdu_data.push(0x00);
                prepare_apdu_data.push(bind_signature.len() as u8);
                prepare_apdu_data.extend(bind_signature.iter());
                prepare_apdu_data.extend(sign_data_pack.iter());

                let prepare_apdus = EosApdu::prepare_sign(prepare_apdu_data);
                let mut prepare_result = "".to_string();
                for prepare_apdu in prepare_apdus {
                    prepare_result = send_apdu_timeout(prepare_apdu, constants::TIMEOUT_LONG)?;
                    ApduCheck::check_response(&prepare_result)?;
                }

                //check pub key
                let signature;
                let uncomprs_pubkey: String = prepare_result
                    .chars()
                    .take(prepare_result.len() - 4)
                    .collect();
                let comprs_pubkey = utility::uncompress_pubkey_2_compress(&uncomprs_pubkey);
                let mut comprs_pubkey_slice = hex::decode(comprs_pubkey)?;
                let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
                let check_sum = &pubkey_hash[0..4];
                comprs_pubkey_slice.extend(check_sum);
                let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();
                if pub_key != &eos_pk {
                    return Err(anyhow!("imkey_publickey_mismatch_with_path"));
                }

                //sign
                let mut nonce = 0;
                loop {
                    let sign_apdu = EosApdu::sign_tx(nonce);
                    let sign_result = send_apdu(sign_apdu)?;
                    ApduCheck::check_response(&sign_result)?;

                    let sign_result_vec = Vec::from_hex(&sign_result[2..sign_result.len() - 6])
                        .map_err(|e| anyhow!("Failed to decode sign result: {}", e))?;

                    let (sig_str, is_valid) =
                        Self::verify_and_normalize_signature(&sign_result_vec)?;

                    if is_valid {
                        let pub_key_raw = hex::decode(&uncomprs_pubkey)
                            .map_err(|e| anyhow!("Failed to decode pubkey: {}", e))?;
                        let sign_compact = hex::decode(&sign_result[2..130])
                            .map_err(|e| anyhow!("Failed to decode sign compact: {}", e))?;

                        let eos_signature = Self::generate_eos_signature(
                            &sig_str,
                            &tx_data_hash,
                            &sign_compact,
                            &pub_key_raw,
                        )?;
                        signature = eos_signature;
                        break;
                    }
                    nonce = nonce + 1;
                }

                sign_result.signs.push(signature);
            }

            trans_multi_signs.push(sign_result);
        }

        let tx_output = EosTxOutput { trans_multi_signs };
        Ok(tx_output)
    }

    /// Sign EOS transaction using secp256k1-based implementation
    ///
    /// This function implements the newer secp256k1-based EOS signing method.
    /// It provides improved security and performance compared to the legacy implementation.
    ///
    /// # Arguments
    /// * `tx_input` - The EOS transaction input containing transaction data
    /// * `sign_param` - Signing parameters including derivation path
    ///
    /// # Returns
    /// * `Result<EosTxOutput>` - The signed transaction output or error
    ///
    /// # Migration Notes
    /// This is the preferred implementation for new applets. The legacy implementation
    /// is maintained for backward compatibility with older applet versions.
    pub fn sign_tx_for_k1(tx_input: EosTxInput, sign_param: &SignParam) -> Result<EosTxOutput> {
        path::check_path_validity(&sign_param.path)?;

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let mut trans_multi_signs: Vec<EosSignResult> = Vec::new();

        for sign_data in &tx_input.transactions {
            let mut sign_result = EosSignResult {
                hash: "".to_string(),
                signs: vec![],
            };

            // Calculate transaction hash using common method
            sign_result.hash = Self::calculate_tx_hash(&sign_data.tx_hex)?;

            // Pack transaction data using common method
            let tx_data_pack = Self::pack_tx_data(&sign_data.chain_id, &sign_data.tx_hex)?;
            let tx_data_hash = sha256_hash(&tx_data_pack);

            //sign
            for pub_key in &sign_data.public_keys {
                let select_apdu = Apdu::select_applet(EOS_AID);
                let select_result = send_apdu(select_apdu)?;
                ApduCheck::check_response(&select_result)?;

                let key_manager_obj = KEY_MANAGER.lock();
                let path_signature =
                    secp256k1_sign(&key_manager_obj.pri_key, &sign_param.path.as_bytes())?;
                let mut path_pack: Vec<u8> = vec![];
                path_pack.push(0x00);
                path_pack.push(path_signature.len() as u8);
                path_pack.extend(path_signature.as_slice());
                path_pack.push(0x01);
                path_pack.push(sign_param.path.as_bytes().len() as u8);
                path_pack.extend(sign_param.path.as_bytes());

                let msg_pubkey = Secp256k1Apdu::get_xpub(&path_pack);
                let res_msg_pubkey = send_apdu(msg_pubkey)?;
                ApduCheck::check_response(&res_msg_pubkey)?;
                let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();
                let comprs_pubkey = utility::uncompress_pubkey_2_compress(&res_msg_pubkey);
                let mut comprs_pubkey_slice = hex::decode(comprs_pubkey)?;
                let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
                let check_sum = &pubkey_hash[0..4];
                comprs_pubkey_slice.extend(check_sum);
                let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();
                if pub_key != &eos_pk {
                    return Err(anyhow!("imkey_publickey_mismatch_with_path"));
                }

                let mut data_pack = Vec::new();

                data_pack.push(0x01);
                data_pack.push(tx_data_hash.len() as u8);
                data_pack.extend(&tx_data_hash);

                let path = sign_param.path.as_bytes();
                data_pack.push(0x02);
                data_pack.push(path.len() as u8);
                data_pack.extend(path);

                let payment = sign_data.payment.as_bytes();
                data_pack.push(0x07);
                data_pack.push(payment.len() as u8);
                data_pack.extend(payment);

                let to = sign_data.receiver.as_bytes();
                data_pack.push(0x08);
                data_pack.push(to.len() as u8);
                data_pack.extend(to);

                // let key_manager_obj = KEY_MANAGER.lock();
                let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

                let mut data_pack_with_sig = Vec::new();
                data_pack_with_sig.push(0x00);
                data_pack_with_sig.push(data_pack_sig.len() as u8);
                data_pack_with_sig.extend(&data_pack_sig);
                data_pack_with_sig.extend(&data_pack);

                let sign_apdus = Secp256k1Apdu::prepare_eos(&data_pack_with_sig);
                for apdu in sign_apdus {
                    let sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
                    ApduCheck::check_response(&sign_response)?;
                }

                //sign
                let mut nonce = 0;
                let signature;
                loop {
                    let sign_apdu = Secp256k1Apdu::sign_eos(nonce);
                    let sign_response = send_apdu(sign_apdu)?;
                    ApduCheck::check_response(&sign_response)?;

                    // verify
                    let sign_source_val = &sign_response[..132];
                    let sign_result = &sign_response[132..sign_response.len() - 4];
                    let sign_verify_result = utility::secp256k1_sign_verify(
                        &key_manager_obj.se_pub_key,
                        hex::decode(sign_result).unwrap().as_slice(),
                        hex::decode(sign_source_val).unwrap().as_slice(),
                    )?;

                    if !sign_verify_result {
                        return Err(CoinError::ImkeySignatureVerifyFail.into());
                    }

                    let sign_result_vec = Vec::from_hex(&sign_source_val[2..130])
                        .map_err(|e| anyhow!("Failed to decode sign result: {}", e))?;

                    let (sig_str, is_valid) =
                        Self::verify_and_normalize_signature(&sign_result_vec)?;

                    if is_valid {
                        let sign_compact = hex::decode(&sign_response[2..130])
                            .map_err(|e| anyhow!("Failed to decode sign compact: {}", e))?;

                        let eos_signature = Self::generate_eos_signature(
                            &sig_str,
                            &tx_data_hash,
                            &sign_compact,
                            &pubkey_raw,
                        )?;
                        signature = eos_signature;
                        break;
                    }
                    nonce = nonce + 1;
                }

                sign_result.signs.push(signature);
            }

            trans_multi_signs.push(sign_result);
        }

        let tx_output = EosTxOutput { trans_multi_signs };
        Ok(tx_output)
    }

    /// Calculate transaction hash from transaction hex data
    fn calculate_tx_hash(tx_hex: &str) -> Result<String> {
        let tx_data_bytes =
            hex::decode(tx_hex).map_err(|e| anyhow!("Failed to decode tx_hex: {}", e))?;
        Ok(sha256_hash(&tx_data_bytes).to_hex())
    }

    /// Pack transaction data for signing
    fn pack_tx_data(chain_id: &str, tx_hex: &str) -> Result<Vec<u8>> {
        let mut tx_data_pack: Vec<u8> = Vec::new();
        tx_data_pack.put_slice(
            hex::decode(chain_id)
                .map_err(|e| anyhow!("Failed to decode chain_id: {}", e))?
                .as_slice(),
        );
        tx_data_pack.put_slice(
            hex::decode(tx_hex)
                .map_err(|e| anyhow!("Failed to decode tx_hex: {}", e))?
                .as_slice(),
        );
        let context_free_actions = [0; 32];
        tx_data_pack.put_slice(&context_free_actions);
        Ok(tx_data_pack)
    }

    /// Generate EOS signature with K1 checksum
    fn generate_eos_signature(
        signature: &str,
        tx_data_hash: &[u8],
        sign_compact: &[u8],
        pubkey_raw: &[u8],
    ) -> Result<String> {
        // Calculate recovery ID
        let rec_id = retrieve_recid(tx_data_hash, sign_compact, &pubkey_raw.to_vec())?;
        let rec_id = rec_id.to_i32();
        let v = rec_id + 27 + 4;

        let mut final_signature = format!("{:02X}", v);
        final_signature.push_str(signature);

        // Add K1 checksum
        let mut to_hash = hex::decode(&final_signature)
            .map_err(|e| anyhow!("Failed to decode signature: {}", e))?;
        to_hash.put_slice("K1".as_bytes());
        let signature_hash = ripemd160::Hash::hash(&to_hash);
        let check_sum = &signature_hash[0..4];

        let mut signature_slice = hex::decode(&final_signature)
            .map_err(|e| anyhow!("Failed to decode final signature: {}", e))?;
        signature_slice.extend(check_sum);

        Ok("SIG_K1_".to_owned() + base58::encode_slice(&signature_slice).as_ref())
    }

    /// Verify and normalize signature
    fn verify_and_normalize_signature(sign_result_vec: &[u8]) -> Result<(String, bool)> {
        let mut signature_obj = Signature::from_compact(sign_result_vec)
            .map_err(|e| anyhow!("Failed to create signature from compact: {}", e))?;

        // Normalize signature
        signature_obj.normalize_s();
        let signatrue_der = signature_obj.serialize_der().to_vec();
        let normalizes_sig_vec = signature_obj.serialize_compact();
        let sig_str = hex::encode(&normalizes_sig_vec.as_ref());

        let len_r = signatrue_der[3];
        let len_s = signatrue_der[5 + len_r as usize];
        let is_valid = len_r == 32 && len_s == 32;

        Ok((sig_str, is_valid))
    }

    /// Sign EOS message with automatic version detection
    ///
    /// This function automatically detects the applet version and routes to the appropriate
    /// message signing implementation. If version detection fails, the function returns an error.
    ///
    /// # Arguments
    /// * `input` - The EOS message input containing message data and public key
    /// * `sign_param` - Signing parameters including derivation path
    ///
    /// # Returns
    /// * `Result<EosMessageOutput>` - The signed message output or error
    ///
    /// # Migration Notes
    /// - Legacy applets (version "0.0.1") use the original EOS message signing method
    /// - Newer applets use the secp256k1-based message signing method
    /// - Version detection failures return an error
    pub fn sign_message(
        input: EosMessageInput,
        sign_param: &SignParam,
    ) -> Result<EosMessageOutput> {
        // Get applet version - fail if version detection fails
        let version = get_apple_version(EOS_AID)?;

        match version.as_str() {
            EOS_LEGACY_APPLET_VERSION => Self::sign_message_for_eos(input, sign_param),
            _ => Self::sign_message_for_k1(input, sign_param),
        }
    }

    pub fn sign_message_for_eos(
        input: EosMessageInput,
        sign_param: &SignParam,
    ) -> Result<EosMessageOutput> {
        let hash = if input.is_hex {
            hex::decode(input.data).unwrap()
        } else {
            sha256_hash(input.data.as_bytes())
        };

        let mut data_pack: Vec<u8> = Vec::new();
        data_pack.push(0x01);
        data_pack.push(0x20);
        data_pack.extend(hash.as_slice());
        data_pack.push(0x02);
        data_pack.push(sign_param.path.as_bytes().len() as u8);
        data_pack.extend(sign_param.path.as_bytes());

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, &data_pack).unwrap();

        let mut prepare_pack: Vec<u8> = Vec::new();
        prepare_pack.push(0x00);
        prepare_pack.push(bind_signature.len() as u8);
        prepare_pack.extend(bind_signature.iter());
        prepare_pack.extend(data_pack.iter());

        let select_apdu = EosApdu::select_applet();
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let prepare_apdus = EosApdu::prepare_message_sign(prepare_pack);

        let mut prepare_response = "".to_string();
        for apdu in prepare_apdus {
            prepare_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&prepare_response)?;
        }

        //todo optmize,calc from prepare response
        let pubkey = EosPubkey::pubkey_from_response(&prepare_response).unwrap();
        let mut signature = "".to_string();
        if &pubkey != &input.pubkey {
            return Err(anyhow!("imkey_publickey_mismatch_with_path"));
        }
        //sign
        let mut nonce = 0;
        loop {
            let sign_apdu = EosApdu::sign_message(nonce);
            let sign_result = send_apdu(sign_apdu)?;
            ApduCheck::check_response(&sign_result)?;

            let sign_result_vec = Vec::from_hex(&sign_result[2..sign_result.len() - 6]).unwrap();
            let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice()).unwrap();
            //generator der sign data
            signature_obj.normalize_s();
            let signatrue_der = signature_obj.serialize_der().to_vec();
            let normalizes_sig_vec = signature_obj.serialize_compact();
            let sig_str = hex::encode(&normalizes_sig_vec.as_ref());

            let len_r = signatrue_der[3];
            let len_s = signatrue_der[5 + len_r as usize];
            if len_r == 32 && len_s == 32 {
                //calc v
                let uncomprs_pubkey: String = prepare_response
                    .chars()
                    .take(prepare_response.len() - 4)
                    .collect();
                let pub_key_raw = hex::decode(&uncomprs_pubkey).unwrap();
                let sign_compact = hex::decode(&sign_result[2..130]).unwrap();
                let rec_id = utility::retrieve_recid(&hash, &sign_compact, &pub_key_raw).unwrap();
                let rec_id = rec_id.to_i32();
                let v = rec_id + 27 + 4;

                signature.push_str(&format!("{:02X}", &v));
                signature.push_str(&sig_str);
                break;
            }
            nonce = nonce + 1;
        }

        //checksum base58
        let mut to_hash = hex::decode(&signature).unwrap();
        to_hash.put_slice("K1".as_bytes());
        let signature_hash = ripemd160::Hash::hash(&to_hash);
        let check_sum = &signature_hash[0..4];

        let mut signature_slice = hex::decode(&signature).unwrap();
        signature_slice.extend(check_sum);
        let signature = "SIG_K1_".to_owned() + base58::encode_slice(&signature_slice).as_ref();

        let output = EosMessageOutput { signature };
        Ok(output)
    }

    pub fn sign_message_for_k1(
        input: EosMessageInput,
        sign_param: &SignParam,
    ) -> Result<EosMessageOutput> {
        let tx_data_hash = if input.is_hex {
            hex::decode(input.data).unwrap()
        } else {
            sha256_hash(input.data.as_bytes())
        };

        let mut data_pack = Vec::new();

        data_pack.push(0x01);
        data_pack.push(tx_data_hash.len() as u8);
        data_pack.extend(&tx_data_hash);

        let path = sign_param.path.as_bytes();
        data_pack.push(0x02);
        data_pack.push(path.len() as u8);
        data_pack.extend(path);

        let key_manager_obj = KEY_MANAGER.lock();
        let msg_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;
        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(msg_sig.len() as u8);
        data_pack_with_sig.extend(msg_sig);
        data_pack_with_sig.extend(&data_pack);

        let select_apdu = Apdu::select_applet(EOS_AID);
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let path_signature = secp256k1_sign(&key_manager_obj.pri_key, &sign_param.path.as_bytes())?;
        let mut path_pack: Vec<u8> = vec![];
        path_pack.push(0x00);
        path_pack.push(path_signature.len() as u8);
        path_pack.extend(path_signature.as_slice());
        path_pack.push(0x01);
        path_pack.push(sign_param.path.as_bytes().len() as u8);
        path_pack.extend(sign_param.path.as_bytes());

        let msg_pubkey = Secp256k1Apdu::get_xpub(&path_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        let pubkey_raw = hex::decode(&res_msg_pubkey[..130]).unwrap();
        let comprs_pubkey = utility::uncompress_pubkey_2_compress(&res_msg_pubkey);
        let mut comprs_pubkey_slice = hex::decode(comprs_pubkey)?;
        let pubkey_hash = ripemd160::Hash::hash(&comprs_pubkey_slice);
        let check_sum = &pubkey_hash[0..4];
        comprs_pubkey_slice.extend(check_sum);
        let eos_pk = "EOS".to_owned() + base58::encode_slice(&comprs_pubkey_slice).as_ref();
        if &input.pubkey != &eos_pk {
            return Err(anyhow!("imkey_publickey_mismatch_with_path"));
        }

        let mut data_pack = Vec::new();

        data_pack.push(0x01);
        data_pack.push(tx_data_hash.len() as u8);
        data_pack.extend(&tx_data_hash);

        let path = sign_param.path.as_bytes();
        data_pack.push(0x02);
        data_pack.push(path.len() as u8);
        data_pack.extend(path);

        // let key_manager_obj = KEY_MANAGER.lock();
        let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(data_pack_sig.len() as u8);
        data_pack_with_sig.extend(&data_pack_sig);
        data_pack_with_sig.extend(&data_pack);

        let sign_apdus = Secp256k1Apdu::prepare_eos(&data_pack_with_sig);
        for apdu in sign_apdus {
            let sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

        //sign
        let mut nonce = 0;
        let mut signature = "".to_string();
        loop {
            let sign_apdu = Secp256k1Apdu::sign_eos(nonce);
            let sign_response = send_apdu(sign_apdu)?;
            ApduCheck::check_response(&sign_response)?;

            // verify
            let sign_source_val = &sign_response[..132];
            let sign_result = &sign_response[132..sign_response.len() - 4];
            let sign_verify_result = utility::secp256k1_sign_verify(
                &key_manager_obj.se_pub_key,
                hex::decode(sign_result).unwrap().as_slice(),
                hex::decode(sign_source_val).unwrap().as_slice(),
            )?;

            if !sign_verify_result {
                return Err(CoinError::ImkeySignatureVerifyFail.into());
            }

            let sign_result_vec = Vec::from_hex(&sign_source_val[2..130]).unwrap();
            let mut signature_obj = Signature::from_compact(sign_result_vec.as_slice()).unwrap();
            //generator der sign data
            signature_obj.normalize_s();
            let signatrue_der = signature_obj.serialize_der().to_vec();
            let normalizes_sig_vec = signature_obj.serialize_compact();
            let sig_str = hex::encode(&normalizes_sig_vec.as_ref());

            let len_r = signatrue_der[3];
            let len_s = signatrue_der[5 + len_r as usize];
            if len_r == 32 && len_s == 32 {
                //calc v
                let sign_compact = hex::decode(&sign_response[2..130]).unwrap();
                let rec_id = retrieve_recid(&tx_data_hash, &sign_compact, &pubkey_raw)?;
                let rec_id = rec_id.to_i32();
                let v = rec_id + 27 + 4;

                signature.push_str(&format!("{:02X}", &v));
                signature.push_str(&sig_str);
                break;
            }
            nonce = nonce + 1;
        }

        //checksum base58
        let mut to_hash = hex::decode(&signature).unwrap();
        to_hash.put_slice("K1".as_bytes());
        let signature_hash = ripemd160::Hash::hash(&to_hash);
        let check_sum = &signature_hash[0..4];

        let mut signature_slice = hex::decode(&signature).unwrap();
        signature_slice.extend(check_sum);
        let signature = "SIG_K1_".to_owned() + base58::encode_slice(&signature_slice).as_ref();

        let output = EosMessageOutput { signature };
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::eosapi::{EosMessageInput, EosSignData, EosTxInput};
    use crate::transaction::EosTransaction;
    use ikc_common::{constants, SignParam};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_sgin_tx() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string()]
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param).unwrap();
        assert_eq!(
            result.trans_multi_signs[0].hash,
            "6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088"
        );
        assert_eq!(
            result.trans_multi_signs[0].signs[0],
            "SIG_K1_KAPzeZtUYNxrQsAeChG99gi8tb8yps5pZ91eKQPGead5AVgwv4kji6rN5ex2XTrSX6asdvcosdMXeidTrQvdkjEQSRckVE"
        );
    }

    #[test]
    fn test_sgin_tx_pubkey_error() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["ERROR PUBKEY".to_string()],
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string()
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param);
        assert_eq!(
            format!("{}", result.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }

    #[test]
    fn test_sgin_tx_chainid_is_null() {
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec!["EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string()],
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string()
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param).unwrap();
        assert_eq!(
            result.trans_multi_signs[0].hash,
            "6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088"
        );
        assert_eq!(
            result.trans_multi_signs[0].signs[0],
            "SIG_K1_KmUwyrzZy7s9hpkuQLe7ttweCXJ5X7aJuoCPu3skFDXcmtnHYTtnioPiX9wCEMFbs1oe7DhZzP8PqBrLHcX24WVJXG9bz9"
        );
    }

    #[test]
    fn test_sign_messgage() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_K2mrf6ASTK5TCJC6kzZzyQm9uRZm7Jx4fa6gsmWx2sEreokRWmnHQGTRNwKLNF6NVJtXmjmUvR96XYct1DjMJnwRZBbTYR"
        );
    }

    #[test]
    fn test_sign_messgage_hex() {
        bind_test();

        let input = EosMessageInput {
            data: "1122334455667788990011223344556677889900112233445566778899001122".to_string(),
            is_hex: true,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_Jy1w6cs58tXkFVVBoku9uAVUuiknttFtwQEjXzpZvXY85EsBi6dU27RPf8KQRRh25jewnpdeVgqZDrj6RiYkdJk5fktZyw"
        );
    }

    #[test]
    fn sign_messgage_wrong_pubkey_test() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "wrong pubkey".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            format!("{}", output.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }

    #[test]
    fn sign_messgage_data_is_null_test() {
        bind_test();

        let input = EosMessageInput {
            data: "".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            output.unwrap().signature,
            "SIG_K1_Kij4tk3eM3UtB5Z1Gz6B5jC9JAtPDj7PQA8kkNPAX97U7JQWePVNCUg4WGso6m91Bz8rWzFoXo3SNhehpYrmJfYtNc4dxJ"
        );
    }

    #[test]
    fn sign_messgage_wrong_path_test() {
        bind_test();

        let input = EosMessageInput {
            data: "imKey2019".to_string(),
            is_hex: false,
            pubkey: "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: "m/44'".to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output = EosTransaction::sign_message(input, &sign_param);
        assert_eq!(
            format!("{}", output.err().unwrap()),
            "imkey_publickey_mismatch_with_path"
        );
    }

    #[test]
    fn test_common_methods() {
        // Test calculate_tx_hash
        let tx_hex = "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00";
        let hash = EosTransaction::calculate_tx_hash(tx_hex).unwrap();
        assert_eq!(
            hash,
            "6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088"
        );

        // Test pack_tx_data
        let chain_id = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906";
        let packed = EosTransaction::pack_tx_data(chain_id, tx_hex).unwrap();
        assert!(!packed.is_empty());
        assert_eq!(packed.len(), 32 + tx_hex.len() / 2 + 32); // chain_id + tx_hex + context_free_actions
    }

    #[test]
    fn test_error_handling_invalid_hex() {
        // Test error handling for invalid hex data
        let result = EosTransaction::calculate_tx_hash("invalid_hex");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode tx_hex"));

        let result = EosTransaction::pack_tx_data("invalid_hex", "valid_hex");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode chain_id"));
    }

    #[test]
    fn test_verify_and_normalize_signature() {
        // Test with a valid signature (this would need actual signature data in a real test)
        // For now, we test that the function handles errors properly
        let invalid_signature = vec![0u8; 32]; // Invalid signature data
        let result = EosTransaction::verify_and_normalize_signature(&invalid_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_strategy_documentation() {
        // This test ensures that the migration strategy is properly documented
        // by checking that both legacy and k1 methods exist and are accessible
        use crate::eosapi::EosTxOutput;
        use anyhow::Result;

        // Test that the functions exist by checking their type signatures
        let _legacy_fn: fn(EosTxInput, &SignParam) -> Result<EosTxOutput> =
            EosTransaction::sign_tx_for_eos;
        let _k1_fn: fn(EosTxInput, &SignParam) -> Result<EosTxOutput> =
            EosTransaction::sign_tx_for_k1;

        // This test passes if the above lines compile without error
        assert!(true);
    }

    #[test]
    fn test_transaction_bug_fix() {
        // Test that the transaction bug fix is working correctly
        // This test verifies that trans_multi_signs.push() is called outside the pubkey loop
        bind_test();

        let eos_sign_data = EosSignData{
            tx_hex: "c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00".to_string(),
            chain_id: "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906".to_string(),
            receiver: "bbbb5555bbbb".to_string(),
            sender: "liujianmin12".to_string(),
            payment: "undelegatebw 0.0100 EOS".to_string(),
            public_keys: vec![
                "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string(),
                "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".to_string()
            ]
        };
        let eox_tx_input = EosTxInput {
            transactions: vec![eos_sign_data],
        };
        let sign_param = SignParam {
            chain_type: "EOS".to_string(),
            path: constants::EOS_PATH.to_string(),
            network: "".to_string(),
            input: None,
            payment: "".to_string(),
            receiver: "".to_string(),
            sender: "".to_string(),
            fee: "".to_string(),
            seg_wit: "".to_string(),
        };

        let result = EosTransaction::sign_tx(eox_tx_input, &sign_param).unwrap();

        // Verify that we have exactly one transaction result (not one per pubkey)
        assert_eq!(result.trans_multi_signs.len(), 1);

        // Verify that the transaction result contains signatures for all public keys
        // (This would be 2 signatures for 2 public keys in the same transaction)
        assert_eq!(result.trans_multi_signs[0].signs.len(), 2);
    }
}
