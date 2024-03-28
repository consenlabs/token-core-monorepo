use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::{constants, https};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CosCheckUpdateRequest {
    pub seid: String,
    pub cos_version: String,
    #[serde(rename = "commandID")]
    pub command_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CosCheckUpdateResponse {
    pub seid: String,
    pub is_latest: bool,
    pub latest_cos_version: Option<String>,
    pub update_type: Option<String>,
    pub description: Option<String>,
    pub is_update_success: bool,
}

impl TsmService for CosCheckUpdateRequest {
    type ReturnData = ServiceResponse<CosCheckUpdateResponse>;

    fn send_message(&mut self) -> Result<ServiceResponse<CosCheckUpdateResponse>> {
        let req_data = serde_json::to_vec_pretty(&self).unwrap();
        let response_data = https::post(constants::TSM_ACTION_COS_CHECK_UPDATE, req_data)?;
        let return_bean: ServiceResponse<CosCheckUpdateResponse> =
            serde_json::from_str(response_data.as_str())?;
        match return_bean.service_res_check() {
            Ok(()) => Ok(return_bean),
            Err(e) => Err(e),
        }
    }
}

impl CosCheckUpdateRequest {
    pub fn build_request_data(seid: String, cos_version: String) -> Self {
        CosCheckUpdateRequest {
            seid,
            cos_version,
            command_id: String::from(constants::TSM_ACTION_COS_CHECK_UPDATE),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::cos_check_update::CosCheckUpdateRequest;
    use crate::device_manager::get_se_id;
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    #[cfg(not(tarpaulin))]
    pub fn cos_check_update_test() {
        // let seid: String = "18080000000000860001010000000106".to_string();
        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();

        let cos_version: String = "1.0.10".to_string();
        assert!(CosCheckUpdateRequest::build_request_data(seid, cos_version)
            .send_message()
            .is_ok());
    }
}
