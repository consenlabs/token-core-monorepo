#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use crate::device_manager::{
    apdu_status_word, get_ble_version, get_cert, get_firmware_version, get_se_id, get_sn,
};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use crate::error::ImkeyError;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use crate::{tsm_post, Result, ServiceResponse};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use anyhow::anyhow;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_common::apdu::ApduCheck;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_common::constants;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_transport::hid_api::hid_connect;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_transport::message::send_apdu;
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::thread;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BleUpgradeRequest {
    pub seid: String,
    pub sn: String,
    pub device_cert: String,
    pub cos_version: String,
    pub ble_version: String,
    pub step_key: String,
    pub status_word: Option<String>,
    #[serde(rename = "commandID")]
    pub command_id: String,
    pub card_ret_data_list: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BleUpgradeResponse {
    pub seid: Option<String>,
    pub cos_version: Option<String>,
    pub ble_version: Option<String>,
    pub instance_aid_list: Option<Vec<String>>,
    pub next_step_key: Option<String>,
    pub apdu_list: Option<Vec<String>>,
}

impl BleUpgradeRequest {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    pub fn ble_upgrade() -> Result<()> {
        let mut request_data = BleUpgradeRequest {
            seid: get_se_id()?,
            sn: get_sn()?,
            device_cert: get_cert()?,
            cos_version: get_firmware_version()?,
            ble_version: get_ble_version()?,
            step_key: "01".to_string(),
            status_word: None,
            command_id: constants::TSM_ACTION_BLE_UPDATE.to_string(),
            card_ret_data_list: None,
        };

        loop {
            let req_data = serde_json::to_vec_pretty(&request_data)?;
            let response_data = tsm_post(constants::TSM_ACTION_BLE_UPDATE, req_data)?;
            let return_bean: ServiceResponse<BleUpgradeResponse> =
                serde_json::from_str(&response_data)?;
            if return_bean.return_code != constants::TSM_RETURN_CODE_SUCCESS {
                return_bean.service_res_check()?;
                continue;
            }

            let next_step_key = return_bean
                .return_data
                .next_step_key
                .ok_or(ImkeyError::ImkeyTsmServerError)?;
            if next_step_key == constants::TSM_END_FLAG {
                return Ok(());
            }

            let apdu_list = return_bean
                .return_data
                .apdu_list
                .ok_or(ImkeyError::ImkeyTsmServerError)?;
            if apdu_list.is_empty() {
                return Err(ImkeyError::ImkeyTsmServerError.into());
            }

            let mut apdu_res = Vec::with_capacity(apdu_list.len());
            let mut last_status_word = None;
            for (index, apdu) in apdu_list.iter().enumerate() {
                let response = send_apdu(apdu.clone())?;
                let status_word = apdu_status_word(&response)?.to_uppercase();

                if next_step_key == "03" {
                    if index == 0 {
                        ApduCheck::check_response(&response)?;
                    } else if index == 5 && status_word == constants::APDU_RSP_APPLET_WRONG_DATA {
                        return Err(anyhow!("imkey_ble_upgrade_fail"));
                    }
                }

                last_status_word = Some(status_word);
                apdu_res.push(response);
            }

            let status_word = last_status_word.ok_or(ImkeyError::ImkeyTsmServerError)?;
            request_data.status_word = Some(status_word.clone());
            request_data.card_ret_data_list = Some(apdu_res);
            request_data.step_key = next_step_key.clone();

            if next_step_key == "03" && status_word == constants::APDU_RSP_SUCCESS {
                reconnect()?;
                request_data.ble_version = get_ble_version()?;
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn reconnect() -> Result<()> {
    thread::sleep(Duration::from_millis(1000));
    for _ in 0..5 {
        if hid_connect(constants::DEVICE_MODEL_NAME).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1000));
    }
    Err(ImkeyError::ImkeyDeviceReconnectFail.into())
}

#[cfg(test)]
mod tests {
    use super::BleUpgradeRequest;
    use ikc_common::constants;

    #[test]
    fn ble_upgrade_contract_uses_expected_request_fields() {
        let request = BleUpgradeRequest {
            seid: "seid".to_string(),
            sn: "sn".to_string(),
            device_cert: "cert".to_string(),
            cos_version: "1.0.0".to_string(),
            ble_version: "3.0.03".to_string(),
            step_key: "01".to_string(),
            status_word: None,
            command_id: constants::TSM_ACTION_BLE_UPDATE.to_string(),
            card_ret_data_list: None,
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["commandID"], "/bleUpdate");
        assert_eq!(value["bleVersion"], "3.0.03");
        assert_eq!(value["stepKey"], "01");
    }
}
