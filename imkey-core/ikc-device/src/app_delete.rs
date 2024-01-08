use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::constants;
use ikc_common::https;
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
        loop {
            println!("send message：{:#?}", self);
            let req_data = serde_json::to_vec_pretty(&self).unwrap();
            let response_data = https::post(constants::TSM_ACTION_APP_DELETE, req_data)?;
            let return_bean: ServiceResponse<AppDeleteResponse> =
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
                            ServiceResponse::<AppDeleteResponse>::apdu_handle(apdu_list)?;
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

impl AppDeleteRequest {
    pub fn build_request_data(seid: String, instance_aid: String, device_cert: String) -> Self {
        AppDeleteRequest {
            seid: seid,
            instance_aid: instance_aid,
            device_cert: device_cert,
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
