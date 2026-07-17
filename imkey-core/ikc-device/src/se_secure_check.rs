use crate::{run_tsm_steps, Result, TsmService, TsmStepRequest, TsmStepResponse};
use ikc_common::constants;
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
        run_tsm_steps(self).map(|_| ())
    }
}

impl TsmStepResponse for SeSecureCheckResponse {
    fn next_step_key(&self) -> Option<&str> {
        self.next_step_key.as_deref()
    }

    fn apdu_list(&self) -> Option<&[String]> {
        self.apdu_list.as_deref()
    }
}

impl TsmStepRequest for SeSecureCheckRequest {
    type Response = SeSecureCheckResponse;

    fn tsm_action(&self) -> &'static str {
        constants::TSM_ACTION_SE_SECURE_CHECK
    }

    fn update_step_result(
        &mut self,
        next_step_key: String,
        card_ret_data_list: Vec<String>,
        status_word: String,
    ) {
        self.card_ret_data_list = Some(card_ret_data_list);
        self.status_word = Some(status_word);
        self.step_key = next_step_key;
    }
}

impl SeSecureCheckRequest {
    pub fn build_request_data(seid: String, sn: String, device_cert: String) -> Self {
        SeSecureCheckRequest {
            seid,
            sn,
            device_cert,
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
        crate::configure_test_tsm_from_env();
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
        crate::configure_test_tsm_from_env();
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
