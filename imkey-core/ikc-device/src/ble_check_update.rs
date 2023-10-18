use crate::ServiceResponse;
use crate::{Result, TsmService};
use ikc_common::{constants, https};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BleCheckUpdateRequest {
    pub seid: String,
    pub ble_version: String,
    #[serde(rename = "commandID")]
    pub command_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BleCheckUpdateResponse {
    pub seid: String,
    pub is_latest: bool,
    pub latest_ble_version: Option<String>,
    pub description: Option<String>,
}

impl TsmService for BleCheckUpdateRequest {
    type ReturnData = ServiceResponse<BleCheckUpdateResponse>;

    fn send_message(&mut self) -> Result<ServiceResponse<BleCheckUpdateResponse>> {
        println!("send message：{:#?}", self);
        let req_data = serde_json::to_vec_pretty(&self).unwrap();
        let response_data = https::post(constants::TSM_ACTION_BLE_CHECK_UPDATE, req_data)?;
        let return_bean: ServiceResponse<BleCheckUpdateResponse> =
            serde_json::from_str(response_data.as_str())?;
        println!("return message：{:#?}", return_bean);
        match return_bean.service_res_check() {
            Ok(()) => Ok(return_bean),
            Err(e) => Err(e),
        }
    }
}

impl BleCheckUpdateRequest {
    pub fn build_request_data(seid: String, ble_version: String) -> Self {
        BleCheckUpdateRequest {
            seid: seid,
            ble_version: ble_version,
            command_id: String::from(constants::TSM_ACTION_BLE_CHECK_UPDATE),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ble_check_update::BleCheckUpdateRequest;
    use crate::device_manager::get_se_id;
    use crate::TsmService;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    #[cfg(not(tarpaulin))]
    pub fn ble_check_update_test() {
        use crate::device_manager::get_ble_version;

        assert!(hid_connect("imKey Pro").is_ok());
        let seid = get_se_id().unwrap();

        let ble_version: String = get_ble_version().unwrap();
        // let ble_version = "3.0.02".to_string();
        assert!(BleCheckUpdateRequest::build_request_data(seid, ble_version)
            .send_message()
            .is_ok());
    }
}
