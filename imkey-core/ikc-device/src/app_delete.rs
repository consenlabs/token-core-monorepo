use crate::{run_tsm_steps, Result, TsmService, TsmStepRequest, TsmStepResponse};
use ikc_common::constants;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppDeleteRequest {
    pub seid: String,
    pub instance_aid: String,
    pub device_cert: String,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppDeleteResponse {
    pub seid: Option<String>,
    pub instance_aid: Option<String>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
}

impl TsmService for AppDeleteRequest {
    type ReturnData = ();

    fn send_message(&mut self) -> Result<()> {
        run_tsm_steps(self).map(|_| ())
    }
}

impl TsmStepResponse for AppDeleteResponse {
    fn next_step_key(&self) -> Option<&str> {
        self.next_step_key.as_deref()
    }

    fn apdu_list(&self) -> Option<&[String]> {
        self.apdu_list.as_deref()
    }
}

impl TsmStepRequest for AppDeleteRequest {
    type Response = AppDeleteResponse;

    fn tsm_action(&self) -> &'static str {
        constants::TSM_ACTION_APP_DELETE
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

impl AppDeleteRequest {
    pub fn build_request_data(seid: String, instance_aid: String, device_cert: String) -> Self {
        AppDeleteRequest {
            seid,
            instance_aid,
            device_cert,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_APP_DELETE),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::app_delete::AppDeleteRequest;
    use crate::device_manager::{get_cert, get_se_id};
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    pub fn app_delete_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let device_cert = get_cert().unwrap();
        let instance_aid = "695F657468".to_string();
        assert!(
            AppDeleteRequest::build_request_data(seid, instance_aid, device_cert)
                .send_message()
                .is_ok()
        );
    }
}
