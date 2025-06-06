use crate::cosmosapi::CosmosTxOutput;
use crate::Result;
use ikc_common::apdu::{ApduCheck, CoinCommonApdu, CosmosApdu, Secp256k1Apdu};
use ikc_common::error::CoinError;
use ikc_common::path::check_path_validity;
use ikc_common::utility::{hex_to_bytes, secp256k1_sign, sha256_hash};
use ikc_common::{constants, utility};
use ikc_device::device_binding::KEY_MANAGER;
use ikc_transport::message::{send_apdu, send_apdu_timeout};
use secp256k1::{self, ecdsa::Signature as SecpSignature};

#[derive(Debug)]
pub struct CosmosTransaction {
    pub sign_data: String,
    pub path: String,
    pub payment_dis: String,
    pub to_dis: String,
    pub fee_dis: String,
}

impl CosmosTransaction {
    pub fn sign(self) -> Result<CosmosTxOutput> {
        check_path_validity(&self.path).unwrap();
        let mut data_pack = Vec::new();

        let hash = sha256_hash(hex_to_bytes(&self.sign_data)?.as_slice());
        //hash
        data_pack.extend([0x01, hash.len() as u8].iter());
        data_pack.extend(hash.iter());
        //path
        data_pack.extend([0x02, self.path.as_bytes().len() as u8].iter());
        data_pack.extend(self.path.as_bytes().iter());
        //payment info in TLV format
        data_pack.extend([0x07, self.payment_dis.as_bytes().len() as u8].iter());
        data_pack.extend(self.payment_dis.as_bytes().iter());
        //receiver info in TLV format
        data_pack.extend([0x08, self.to_dis.as_bytes().len() as u8].iter());
        data_pack.extend(self.to_dis.as_bytes().iter());
        //fee info in TLV format
        data_pack.extend([0x09, self.fee_dis.as_bytes().len() as u8].iter());
        data_pack.extend(self.fee_dis.as_bytes().iter());

        let key_manager_obj = KEY_MANAGER.lock();
        let data_pack_sig = secp256k1_sign(&key_manager_obj.pri_key, &data_pack)?;

        let mut data_pack_with_sig = Vec::new();
        data_pack_with_sig.push(0x00);
        data_pack_with_sig.push(data_pack_sig.len() as u8);
        data_pack_with_sig.extend(&data_pack_sig);
        data_pack_with_sig.extend(&data_pack);

        let select_apdu = CosmosApdu::select_applet();
        let select_result = send_apdu(select_apdu)?;
        ApduCheck::check_response(&select_result)?;

        let mut sign_response = "".to_string();
        let sign_apdus = Secp256k1Apdu::sign(&data_pack_with_sig);
        for apdu in sign_apdus {
            sign_response = send_apdu_timeout(apdu, constants::TIMEOUT_LONG)?;
            ApduCheck::check_response(&sign_response)?;
        }

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

        let sign_compact = hex::decode(&sign_response[2..130]).unwrap();

        let mut signature_obj = SecpSignature::from_compact(sign_compact.as_slice()).unwrap();
        signature_obj.normalize_s();
        let normalizes_sig_vec = signature_obj.serialize_compact();
        let signature = base64::encode(&normalizes_sig_vec.as_ref());

        let output = CosmosTxOutput { signature };
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::CosmosTransaction;
    use ikc_common::constants;
    use ikc_common::utility::{hex_to_bytes, secp256k1_sign};
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_ecsign() {
        let sign_pack = hex_to_bytes(
            "0120D560F6EAB74C1D26DD5FAB27B9F700F4C371AC76A82E9A2E534269322D129E2F070008000900",
        )
        .unwrap();
        let private_key =
            hex_to_bytes("F85B222058BBEFFF888AAF7AD1D08B0C9C5FF719027F7DB69859B72A17B28749")
                .unwrap();
        let prepare_data = secp256k1_sign(&private_key, &sign_pack.as_slice()).unwrap();
        let prepare_data_hex = hex::encode(&prepare_data);
        assert_eq!(prepare_data_hex,
                   "3045022100a773a750391978586598843f89921d33083f670049906dc68ad312867df2826d0220312d22dcc102d8ba2a86972c7c73f082c53b29ef0a04ac630def935ed996d9c2"
        );
    }

    #[test]
    fn test_base64() {
        let hex = "477135B0DF08980F927D1569A780B4C4D24DA503BBCF98B87F606C29D47110FB654A8BAC272C80860018D77039563644209011717F4A69691F6B27C44C48002E".to_string();
        let bytes = hex::decode(&hex).unwrap();
        let base64 = base64::encode(&bytes);
        assert_eq!(base64,
                   "R3E1sN8ImA+SfRVpp4C0xNJNpQO7z5i4f2BsKdRxEPtlSousJyyAhgAY13A5VjZEIJARcX9KaWkfayfETEgALg=="
        );
    }

    #[test]
    fn test_sign_delegate() {
        bind_test();
        let sign_data= "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
        let input = CosmosTransaction {
            sign_data,
            path: constants::COSMOS_PATH.to_string(),
            payment_dis: "".to_string(),
            to_dis: "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt".to_string(),
            fee_dis: "0.00075 atom".to_string(),
        };
        let cosmos_tx_output = input.sign().unwrap();
        assert_eq!("355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==", cosmos_tx_output.signature);
    }

    #[test]
    fn test_sign_payment_dis() {
        bind_test();
        let sign_data = "7b226163636f756e745f6e756d626572223a2231323334353637383930222c22636861696e5f6964223a2274656e6465726d696e745f74657374222c22666565223a7b22616d6f756e74223a5b7b22616d6f756e74223a2230222c2264656e6f6d223a22227d5d2c22676173223a223231393036227d2c226d656d6f223a22222c226d736773223a5b7b2274797065223a22636f736d6f732d73646b2f4d736744656c6567617465222c2276616c7565223a7b22616d6f756e74223a5b7b22616d6f756e74223a223130222c2264656e6f6d223a2261746f6d227d5d2c2264656c656761746f725f61646472657373223a22636f736d6f73317930613873633561797635326632666d35743768723267383871676c6a7a6b346a637a373866222c2276616c696461746f725f61646472657373223a22636f736d6f7376616c6f706572317a6b757072383368727a6b6e33757035656c6b747a63713374756674386e78736d7764716770227d7d5d2c2273657175656e6365223a2231323334353637383930227d".to_string();
        let input = CosmosTransaction {
            sign_data,
            path: constants::COSMOS_PATH.to_string(),
            payment_dis: "0.001 ATOM".to_string(),
            to_dis: "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt".to_string(),
            fee_dis: "0.00075 atom".to_string(),
        };
        let cosmos_tx_output = input.sign().unwrap();
        assert_eq!("h4//cOYLTiDYbdw+1NVZufwppIAcEQ1xsWMYcCdcGtsu4xSnYStxyJgIa57445sHnXgWP84VvnQ5geoUZAKxlQ==", cosmos_tx_output.signature);
    }

    #[test]
    fn test_sort_vec() {
        let mut vec = Vec::new();
        vec.push("richard");
        vec.push("charles");
        vec.push("peter");
        vec.push("from");
        vec.push("to");
        vec.push("delegate");
        vec.push("valide");

        vec.sort();
        assert_eq!(
            format!("{:?}", vec),
            "[\"charles\", \"delegate\", \"from\", \"peter\", \"richard\", \"to\", \"valide\"]"
        );
    }
}
