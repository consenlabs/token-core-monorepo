use crate::Result;
use ikc_common::apdu::{Apdu, ApduCheck, Ed25519Apdu};
use ikc_common::constants::TON_AID;
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{hex_to_bytes, secp256k1_sign, secp256k1_sign_verify};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::send_apdu;
use tonlib_core::{
    cell::StateInit,
    types::TonAddress as TonAddressLib,
    wallet::{WalletVersion, DEFAULT_WALLET_ID, DEFAULT_WALLET_ID_V5R1},
};

pub struct TonAddress();
impl TonAddress {
    pub fn from_public_key(
        public_key: &[u8],
        network: &str,
        contract_code: &str,
    ) -> Result<String> {
        let wallet_version = WalletVersion::from_code(contract_code)?;

        let wallet_id = match wallet_version {
            WalletVersion::V5R1 => DEFAULT_WALLET_ID_V5R1,
            _ => DEFAULT_WALLET_ID,
        };

        let is_testnet = match network.to_uppercase().as_str() {
            "TESTNET" => true,
            _ => false,
        };

        let data = wallet_version.initial_data(&public_key, wallet_id)?;
        let code = wallet_version.code()?;
        let state_init_hash = StateInit::create_account_id(&code, &data)?;

        let addr = TonAddressLib::new(0, &state_init_hash);
        //true:Non-bounceable false:Bounceable
        let address = addr.to_base64_url_flags(true, is_testnet);

        Ok(address)
    }

    pub fn get_public_key(path: &str) -> Result<Vec<u8>> {
        check_path_validity(path)?;

        let select_apdu = Apdu::select_applet(TON_AID);
        let select_response = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_response)?;

        let key_manager_obj = KEY_MANAGER.lock();
        let bind_signature = secp256k1_sign(&key_manager_obj.pri_key, path.as_bytes())?;

        let mut apdu_pack: Vec<u8> = vec![];
        apdu_pack.push(0x00);
        apdu_pack.push(bind_signature.len() as u8);
        apdu_pack.extend(bind_signature.as_slice());
        apdu_pack.push(0x01);
        apdu_pack.push(path.as_bytes().len() as u8);
        apdu_pack.extend(path.as_bytes());

        //get public
        let msg_pubkey = Ed25519Apdu::get_xpub(&apdu_pack);
        let res_msg_pubkey = send_apdu(msg_pubkey)?;
        ApduCheck::check_response(&res_msg_pubkey)?;

        // let pubkey = &res_msg_pubkey[..64];
        let pubkey = hex_to_bytes(&res_msg_pubkey[..64])?;
        let sign_result = &res_msg_pubkey[64..res_msg_pubkey.len() - 4];

        //verify
        let sign_verify_result = secp256k1_sign_verify(
            &key_manager_obj.se_pub_key,
            hex::decode(sign_result).unwrap().as_slice(),
            &pubkey,
        )?;
        if !sign_verify_result {
            return Err(CoinError::ImkeySignatureVerifyFail.into());
        }

        Ok(pubkey)
    }

    pub fn get_address(path: &str, network: &str, contract_code: &str) -> Result<String> {
        let public_key = TonAddress::get_public_key(path)?;
        let address = TonAddress::from_public_key(&public_key, network, contract_code)?;
        Ok(address)
    }

    pub fn display_address(path: &str, network: &str, contract_code: &str) -> Result<String> {
        let address = TonAddress::get_address(path, network, contract_code)?;
        let reg_apdu = Ed25519Apdu::register_address("TON".as_bytes(), address.as_bytes());
        let res_reg = send_apdu(reg_apdu)?;
        ApduCheck::check_response(&res_reg)?;
        Ok(address)
    }
}

#[cfg(test)]
mod test {
    use crate::address::TonAddress;
    use ikc_common::constants::{TON_AID, TON_PATH};
    use ikc_common::hex::FromHex;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_address_from_public() {
        let pub_key = Vec::from_hex_auto(
            "0x8dcc5a70ba6ccb4ac1704fec5479327100065c9fab8ef173cc64aea3459fb87b",
        )
        .unwrap();
        let address = TonAddress::from_public_key(&pub_key, "MAINNET", "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=")
            .expect("generator address error");
        assert_eq!("UQCpecuOS5riOEjasciyaOkKUdjjvIjsPjhxWsk4z9oy6rV8", address);

        let address = TonAddress::from_public_key(&pub_key, "TESTNET", "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=")
            .expect("generator address error");
        assert_eq!("0QCpecuOS5riOEjasciyaOkKUdjjvIjsPjhxWsk4z9oy6g72", address);
    }

    #[test]
    fn test_get_address() {
        bind_test();
        let address = TonAddress::get_address(TON_PATH, "MAINNET", "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=")
            .expect("get address error");
        assert_eq!("16NhUkUTkYsYRjMD22Sop2DF8MAXUsjPcYtgHF3t1ccmohx1", address);
        let address = TonAddress::get_address(TON_PATH, "TESTNET", "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=")
            .expect("get address error");
        assert_eq!("Fde6T2hDvbvuQrRizcjPoQNZTxuVSbTp78zwFcxzUb86xXS", address);
    }

    #[test]
    fn test_display_address() {
        bind_test();
        let address =
            TonAddress::display_address(TON_PATH, "MAINNET", "").expect("display address error");
        assert_eq!("16NhUkUTkYsYRjMD22Sop2DF8MAXUsjPcYtgHF3t1ccmohx1", address);
        let address =
            TonAddress::display_address(TON_PATH, "TESTNET", "").expect("get address error");
        assert_eq!("Fde6T2hDvbvuQrRizcjPoQNZTxuVSbTp78zwFcxzUb86xXS", address);
    }
}
