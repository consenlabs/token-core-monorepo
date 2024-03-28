use crate::error::ImkeyError;
use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::constants;
use ikc_common::https;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCertCheckRequest {
    pub seid: String,
    pub sn: String,
    pub device_cert: String,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCertCheckResponse {
    pub seid: Option<String>,
    pub verify_result: Option<bool>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
}

impl TsmService for DeviceCertCheckRequest {
    type ReturnData = ();

    fn send_message(&mut self) -> Result<()> {
        let req_data = serde_json::to_vec_pretty(&self).unwrap();
        let response_data = https::post(constants::TSM_ACTION_DEVICE_CERT_CHECK, req_data)?;
        let return_bean: ServiceResponse<DeviceCertCheckResponse> =
            serde_json::from_str(response_data.as_str())?;

        match return_bean.service_res_check() {
            Ok(()) => {
                if return_bean.return_data.verify_result.unwrap() {
                    return Ok(());
                }
                Err(ImkeyError::ImkeySeCertInvalid.into())
            }
            Err(e) => Err(e),
        }
    }
}

impl DeviceCertCheckRequest {
    pub fn build_request_data(seid: String, sn: String, device_cert: String) -> Self {
        DeviceCertCheckRequest {
            seid,
            sn,
            device_cert,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_DEVICE_CERT_CHECK),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::device_binding::KEY_MANAGER;
    use crate::device_cert_check::DeviceCertCheckRequest;
    use crate::device_manager::{get_se_id, get_sn};
    use crate::TsmService;
    use ikc_common::apdu::{Apdu, ImkApdu};
    use ikc_common::constants::IMK_AID;
    use ikc_transport::hid_api::hid_connect;
    use ikc_transport::message::send_apdu;

    #[test]
    #[cfg(not(tarpaulin))]
    pub fn device_cert_check_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let sn = get_sn().unwrap();

        ////test environment cert
        // let device_cert = "7F2181C5931018080000000000860001010000000106420200015F200401020304950200805F2504201810145F2404FFFFFFFF53007F4947B0410403089D8A83A87F24D906303A49D39669D17B0F7AB76EB098A65AFEF31154E75DEE5B87B69CBF78F11E831A4961C8A8F031C2869EA0716C798F76F5E91338DC35F002DFFE5F37473045022100EB46DC605568CF8D5051CD67CEC234C66FC6E2561D2FE57D8DDF8D4D204695A6022009C246BE380DD2A8972807D2AE2A0FE22877408717E239AAA0C2530524714A48".to_string();

        let key_manager_obj = KEY_MANAGER.lock();
        //gen bindchec apdu
        let bind_check_apdu = ImkApdu::bind_check(&key_manager_obj.pub_key);
        //send bindcheck command and get return data
        send_apdu(Apdu::select_applet(IMK_AID));
        let bind_check_apdu_resp_data = send_apdu(bind_check_apdu).unwrap();
        let se_pub_key_cert: String =
            String::from(&bind_check_apdu_resp_data[2..(bind_check_apdu_resp_data.len() - 4)]);
        assert!(
            DeviceCertCheckRequest::build_request_data(seid, sn, se_pub_key_cert)
                .send_message()
                .is_ok()
        );
    }
}
