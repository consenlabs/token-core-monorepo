use crate::ServiceResponse;
use crate::{run_tsm_steps, Result, TsmService, TsmStepRequest, TsmStepResponse};
use ikc_common::constants;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateRequest {
    pub seid: String,
    pub instance_aid: String,
    pub device_cert: String,
    pub sdk_version: Option<String>,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateResponse {
    pub seid: Option<String>,
    pub instance_aid: Option<String>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
    pub address_register_list: Option<Vec<String>>,
}

impl TsmService for AppUpdateRequest {
    type ReturnData = ServiceResponse<AppUpdateResponse>;

    fn send_message(&mut self) -> Result<ServiceResponse<AppUpdateResponse>> {
        run_tsm_steps(self)
    }
}

impl TsmStepResponse for AppUpdateResponse {
    fn next_step_key(&self) -> Option<&str> {
        self.next_step_key.as_deref()
    }

    fn apdu_list(&self) -> Option<&[String]> {
        self.apdu_list.as_deref()
    }
}

impl TsmStepRequest for AppUpdateRequest {
    type Response = AppUpdateResponse;

    fn tsm_action(&self) -> &'static str {
        constants::TSM_ACTION_APP_UPDATE
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

impl AppUpdateRequest {
    pub fn build_request_data(
        seid: String,
        instance_aid: String,
        device_cert: String,
        sdk_version: Option<String>,
    ) -> Self {
        AppUpdateRequest {
            seid,
            instance_aid,
            device_cert,
            sdk_version,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_APP_UPDATE),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::app_update::AppUpdateRequest;
    use crate::device_manager::{get_cert, get_se_id};
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    pub fn app_update_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let device_cert = get_cert().unwrap();
        let instance_aid = "695F627463".to_string();
        let exe_result =
            AppUpdateRequest::build_request_data(seid, instance_aid, device_cert, None)
                .send_message();
        assert!(exe_result.is_ok());
    }

    #[test]
    pub fn app_update_error_test() {
        crate::configure_test_tsm_from_env();
        let seid = "00000000000000000000000000000000".to_string();
        let device_cert = "00000000000000000000000000".to_string();
        let instance_aid = "695F627463".to_string();
        assert!(
            AppUpdateRequest::build_request_data(seid, instance_aid, device_cert, None)
                .send_message()
                .is_err()
        );
    }
}
