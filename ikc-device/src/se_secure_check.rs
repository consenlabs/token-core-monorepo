use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::constants;
use ikc_common::https;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SeSecureCheckRequest {
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
pub struct SeSecureCheckResponse {
    pub seid: Option<String>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
}

impl TsmService for SeSecureCheckRequest {
    type ReturnData = ();

    fn send_message(&mut self) -> Result<()> {
        loop {
            println!("send message：{:#?}", self);
            let req_data = serde_json::to_vec_pretty(&self).unwrap();
            let response_data = https::post(constants::TSM_ACTION_SE_SECURE_CHECK, req_data)?;
            let return_bean: ServiceResponse<SeSecureCheckResponse> =
                serde_json::from_str(response_data.as_str())?;
            println!("return message：{:#?}", return_bean);
            if return_bean._ReturnCode == constants::TSM_RETURN_CODE_SUCCESS {
                //check if end
                let next_step_key = return_bean._ReturnData.next_step_key.unwrap();
                if constants::TSM_END_FLAG.eq(next_step_key.as_str()) {
                    return Ok(());
                }

                match return_bean._ReturnData.apdu_list {
                    Some(apdu_list) => {
                        let handle_result =
                            ServiceResponse::<SeSecureCheckResponse>::apdu_handle(apdu_list)?;
                        self.card_ret_data_list = Some(handle_result.0);
                        self.status_word = Some(handle_result.1);
                        self.step_key = next_step_key;
                    }
                    None => (),
                }
            } else {
                return_bean.service_res_check()?;
            }
        }
    }
}

impl SeSecureCheckRequest {
    pub fn build_request_data(seid: String, sn: String, device_cert: String) -> Self {
        SeSecureCheckRequest {
            seid: seid,
            sn: sn,
            device_cert: device_cert,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_SE_SECURE_CHECK),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::device_manager::{get_cert, get_se_id, get_sn};
    use crate::se_secure_check::SeSecureCheckRequest;
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    pub fn se_secure_check_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let sn: String = get_sn().unwrap();
        let device_cert = get_cert().unwrap();
        assert!(
            SeSecureCheckRequest::build_request_data(seid, sn, device_cert)
                .send_message()
                .is_ok()
        );
    }

    #[test]
    pub fn se_secure_check_error_test() {
        let seid = "00000000000000000000000000000000".to_string();
        let sn = "000001".to_string();
        let device_cert = "00000000000000000000000000000000".to_string();
        assert!(
            SeSecureCheckRequest::build_request_data(seid, sn, device_cert)
                .send_message()
                .is_err()
        );
    }
}
