use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::constants;
use ikc_common::https;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthCodeStorageRequest {
    pub seid: String,
    pub auth_code: String,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthCodeStorageResponse {
    pub seid: Option<String>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
}

impl TsmService for AuthCodeStorageRequest {
    type ReturnData = ();

    fn send_message(&mut self) -> Result<()> {
        println!("send message：{:#?}", self);
        let req_data = serde_json::to_vec_pretty(&self).unwrap();
        let response_data = https::post(constants::TSM_ACTION_AUTHCODE_STORAGE, req_data)?;
        let return_bean: ServiceResponse<AuthCodeStorageResponse> =
            serde_json::from_str(response_data.as_str())?;
        println!("return message：{:#?}", return_bean);
        return_bean.service_res_check()
    }
}

impl AuthCodeStorageRequest {
    pub fn build_request_data(seid: String, auth_code: String) -> Self {
        AuthCodeStorageRequest {
            seid: seid,
            auth_code: auth_code,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_AUTHCODE_STORAGE),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::auth_code_storage::AuthCodeStorageRequest;
    use crate::device_manager::get_se_id;
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    pub fn auth_code_storage_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let auth_code: String = "33FE1AEAEB429C2C3798EBE67B709DBB7140FFD6FA9E8D5FF5476919B618904F88C3B52D8D05FAE7F88E9FAEC576A1EAFAF4D48B7B6670CBB368A34D6FD67F93F6BC008746BDB349A020FE88FBF566CC6ADE322E6B17325DD9AEF310495BECCE4634B61621FE776F4D217B8764CAC0FFD276FD4917CEA3EBECCF19D2EB7237DB395B9B68BA40FC6B040C257658E8D6D0DE9A67E49DF86D065BE1831B02751BBA00F8EDE4242859221C1D7DEF7547D1ADB43188D2A074AAA0C980A822B8B5363D8CCE81E829F83DA6E8D7530AD6F2785F07E417AE59AD2A414D5A203D3052F0106AC801C054374E6F4ADD024C9026E3D4DA9F947B0097F4E10B20E1B684AA6006".to_string();
        assert!(AuthCodeStorageRequest::build_request_data(seid, auth_code)
            .send_message()
            .is_ok());
    }
}
