use crate::device_manager::get_ble_version;
use crate::device_manager::{get_cert, get_firmware_version, get_se_id, get_sn};
use crate::error::ImkeyError;
use crate::Result;
use crate::ServiceResponse;
use anyhow::anyhow;
use ikc_common::apdu::ApduCheck;
use ikc_common::{constants, https};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_transport::hid_api::hid_connect;
use ikc_transport::message::send_apdu;
use serde::{Deserialize, Serialize};
use std::thread;
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
        let device_cert = get_cert()?;
        let seid = get_se_id()?;
        let sn = get_sn()?;
        let cos_version = get_firmware_version()?;
        let ble_version = get_ble_version()?;
        let mut request_data = BleUpgradeRequest {
            seid,
            sn,
            device_cert,
            cos_version,
            ble_version,
            step_key: "01".to_string(),
            status_word: None,
            command_id: String::from(constants::TSM_ACTION_BLE_UPDATE),
            card_ret_data_list: None,
        };
        let mut status_word;
        loop {
            let req_data = serde_json::to_vec_pretty(&request_data).unwrap();
            let response_data = https::post(constants::TSM_ACTION_BLE_UPDATE, req_data)?;
            let return_bean: ServiceResponse<BleUpgradeResponse> =
                serde_json::from_str(response_data.as_str())?;
            if return_bean.return_code == constants::TSM_RETURN_CODE_SUCCESS {
                let next_step_key = return_bean.return_data.next_step_key.unwrap();
                if constants::TSM_END_FLAG.eq(next_step_key.as_str()) {
                    return Ok(());
                }
                let mut apdu_res: Vec<String> = vec![];
                match return_bean.return_data.apdu_list {
                    Some(apdu_list) => {
                        for (index_val, apdu_val) in apdu_list.iter().enumerate() {
                            let res = send_apdu(apdu_val.to_string())?;
                            apdu_res.push(res.clone());
                            status_word = String::from(&res[res.len() - 4..]);
                            if "03".eq(next_step_key.as_str()) {
                                if index_val == 0 {
                                    ApduCheck::check_response(&res)?;
                                } else if index_val == 5 && "6A80".eq(&status_word.to_uppercase()) {
                                    return Err(anyhow!("imkey_ble_upgrade_fail{}", response_data));
                                }
                            }

                            if index_val == apdu_list.len() - 1 {
                                request_data.status_word = Some(status_word.clone());
                                if constants::APDU_RSP_SUCCESS.eq(&status_word) {
                                    if "03".eq(next_step_key.as_str()) {
                                        reconnect()?;
                                        request_data.ble_version = get_ble_version()?;
                                    }
                                }
                            }
                        }
                        request_data.card_ret_data_list = Some(apdu_res);
                    }
                    None => (),
                }
                request_data.step_key = next_step_key;
            } else {
                return_bean.service_res_check()?;
            }
        }
    }
}

/**
reconnect device
*/
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn reconnect() -> Result<()> {
    thread::sleep(Duration::from_millis(1000));

    for _ in 0..5 {
        if hid_connect(constants::DEVICE_MODEL_NAME).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1000));
        continue;
    }

    Err(ImkeyError::ImkeyDeviceReconnectFail.into())
}

#[cfg(test)]
mod tests {
    use crate::ble_upgrade::BleUpgradeRequest;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    #[cfg(not(tarpaulin))]
    fn ble_upgrade_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        assert!(BleUpgradeRequest::ble_upgrade().is_ok());
    }
}
