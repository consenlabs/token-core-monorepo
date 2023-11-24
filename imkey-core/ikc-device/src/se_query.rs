use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::constants;
use ikc_common::https;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SeQueryRequest {
    pub seid: String,
    pub sn: String,
    pub sdk_version: Option<String>,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SeQueryResponse {
    pub seid: Option<String>,
    pub next_step_key: Option<String>,
    pub sn: Option<String>,
    pub sdk_mode: Option<String>,
    pub available_app_bean_list: Option<Vec<AvailableAppBean>>,
    pub status: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AvailableAppBean {
    pub app_logo: Option<String>,
    pub install_mode: Option<String>,
    pub installed_version: Option<String>,
    pub instance_aid: Option<String>,
    pub last_updated: Option<String>,
    pub latest_version: Option<String>,
}

impl TsmService for SeQueryRequest {
    type ReturnData = ServiceResponse<SeQueryResponse>;

    fn send_message(&mut self) -> Result<ServiceResponse<SeQueryResponse>> {
        let req_data = serde_json::to_vec_pretty(&self).unwrap();
        let response_data = https::post(constants::TSM_ACTION_SE_QUERY, req_data)?;
        let mut return_bean: ServiceResponse<SeQueryResponse> =
            serde_json::from_str(response_data.as_str())?;

        match return_bean.service_res_check() {
            Ok(()) => {
                return_bean.return_data.status =
                    Some(constants::IMKEY_DEV_STATUS_LATEST.to_string());
                Ok(return_bean)
            }
            Err(e) => {
                if constants::TSM_RETURNCODE_DEV_INACTIVATED.eq(return_bean.return_code.as_str()) {
                    return Ok(return_bean);
                }
                Err(e)
            }
        }
    }
}

impl SeQueryRequest {
    pub fn build_request_data(seid: String, sn: String, sdk_version: Option<String>) -> Self {
        SeQueryRequest {
            seid,
            sn,
            sdk_version,
            step_key: String::from("01"),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_SE_QUERY),
            card_ret_data_list: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::device_manager::{get_se_id, get_sn};
    use crate::se_query::SeQueryRequest;
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    fn se_query_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();
        let sn = get_sn().unwrap();
        assert!(SeQueryRequest::build_request_data(seid, sn, None)
            .send_message()
            .is_ok());
    }

    #[test]
    pub fn se_query_error_test() {
        let seid = "00000000000000000000000000000000".to_string();
        let sn = "000001".to_string();
        assert!(SeQueryRequest::build_request_data(seid, sn, None)
            .send_message()
            .is_err());
    }
}
