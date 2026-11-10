pub mod app_delete;
pub mod app_download;
pub mod app_update;
pub mod auth_code_storage;
pub mod device_binding;
pub mod device_cert_check;
pub mod se_activate;
pub mod se_query;
pub mod se_secure_check;
extern crate ikc_common;
pub mod async_device_manager;
pub mod ble_upgrade;
pub mod cos_upgrade;
pub mod device_manager;
pub mod deviceapi;
pub mod key_manager;
#[macro_use]
extern crate lazy_static;
extern crate ikc_transport;
pub mod error;
extern crate anyhow;
use core::result;
pub type Result<T> = result::Result<T, anyhow::Error>;
use crate::error::ImkeyError;
use ikc_common::error::ApduError;
use ikc_common::{constants, https};
use ikc_transport::message;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub mod cos_check_update;

// Called only by hardware-test entry points, including `bind_test` consumers in
// the coin crates. Production clients configure TSM through `configure_tsm`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn configure_test_tsm_from_env() {
    if let Ok(base_url) = std::env::var("IMKEY_TSM_TEST_URL") {
        ikc_common::tsm::configure_tsm_url(&base_url)
            .expect("IMKEY_TSM_TEST_URL must contain a valid TSM base URL");
    }
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceResponse<T> {
    #[serde(rename = "_ReturnCode")]
    pub return_code: String,
    #[serde(rename = "_ReturnMsg")]
    pub return_msg: String,
    #[serde(rename = "_ReturnData")]
    pub return_data: T,
}

pub trait TsmService {
    type ReturnData;
    fn send_message(&mut self) -> Result<Self::ReturnData>;
}

pub fn tsm_post(action: &str, req_data: Vec<u8>) -> Result<String> {
    https::post(action, req_data)
}

pub trait TsmStepResponse {
    fn next_step_key(&self) -> Option<&str>;
    fn apdu_list(&self) -> Option<&[String]>;
}

pub trait TsmStepRequest: Serialize {
    type Response: DeserializeOwned + TsmStepResponse;

    fn tsm_action(&self) -> &'static str;
    fn update_step_result(
        &mut self,
        next_step_key: String,
        card_ret_data_list: Vec<String>,
        status_word: String,
    );
}

pub fn run_tsm_steps<T>(request: &mut T) -> Result<ServiceResponse<T::Response>>
where
    T: TsmStepRequest,
{
    loop {
        let req_data = serde_json::to_vec_pretty(request)?;
        let response_data = tsm_post(request.tsm_action(), req_data)?;
        let return_bean: ServiceResponse<T::Response> =
            serde_json::from_str(response_data.as_str())?;
        if return_bean.return_code != constants::TSM_RETURN_CODE_SUCCESS {
            return_bean.service_res_check()?;
            continue;
        }

        let next_step_key = return_bean
            .return_data
            .next_step_key()
            .ok_or(ImkeyError::ImkeyTsmServerError)?
            .to_string();
        if constants::TSM_END_FLAG.eq(next_step_key.as_str()) {
            return Ok(return_bean);
        }

        let apdu_list = return_bean
            .return_data
            .apdu_list()
            .ok_or(ImkeyError::ImkeyTsmServerError)?
            .to_vec();
        let (card_ret_data_list, status_word) =
            ServiceResponse::<T::Response>::apdu_handle(apdu_list)?;
        request.update_step_result(next_step_key, card_ret_data_list, status_word);
    }
}

impl<T> ServiceResponse<T> {
    pub fn service_res_check(&self) -> Result<()> {
        match self.return_code.as_str() {
            constants::TSM_RETURN_CODE_SUCCESS => Ok(()),
            constants::TSM_RETURNCODE_APP_DELETE_FAIL => {
                Err(ImkeyError::ImkeyTsmAppDeleteFail.into())
            }
            constants::TSM_RETURNCODE_DEVICE_ILLEGAL => {
                Err(ImkeyError::ImkeyTsmDeviceIllegal.into())
            }
            constants::TSM_RETURNCODE_OCE_CERT_CHECK_FAIL => {
                Err(ImkeyError::ImkeyTsmOceCertCheckFail.into())
            }
            constants::TSM_RETURNCODE_DEVICE_STOP_USING => {
                Err(ImkeyError::ImkeyTsmDeviceStopUsing.into())
            }
            constants::TSM_RETURNCODE_RECEIPT_CHECK_FAIL => {
                Err(ImkeyError::ImkeyTsmReceiptCheckFail.into())
            }
            constants::TSM_RETURNCODE_DEV_INACTIVATED => {
                Err(ImkeyError::ImkeyTsmDeviceNotActivated.into())
            }
            constants::TSM_RETURNCODE_APP_DOWNLOAD_FAIL => {
                Err(ImkeyError::ImkeyTsmAppDownloadFail.into())
            }
            constants::TSM_RETURNCODE_AUTH_CODE_HANDLE_FAIL => {
                Err(ImkeyError::ImkeyTsmAuthCodeCiphertextStorageFail.into())
            }
            constants::TSM_RETURNCODE_COS_CHECK_UPDATE_FAIL => {
                Err(ImkeyError::ImkeyTsmCosCheckUpdateFail.into())
            }
            constants::TSM_RETURNCODE_COS_INFO_NO_CONF => {
                Err(ImkeyError::ImkeyTsmCosInfoNoConf.into())
            }
            constants::TSM_RETURNCODE_COS_UPGRADE_FAIL => {
                Err(ImkeyError::ImkeyTsmCosUpgradeFail.into())
            }
            constants::TSM_RETURNCODE_UPLOAD_COS_VERSION_IS_NULL => {
                Err(ImkeyError::ImkeyTsmUploadCosVersionIsNull.into())
            }
            constants::TSM_RETURNCODE_SWITCH_BL_STATUS_FAIL => {
                Err(ImkeyError::ImkeyTsmSwitchBlStatusFail.into())
            }
            constants::TSM_RETURNCODE_WRITE_WALLET_ADDRESS_FAIL => {
                Err(ImkeyError::ImkeyTsmWriteWalletAddressFail.into())
            }
            constants::TSM_RETURNCODE_DEVICE_CHECK_FAIL => {
                Err(ImkeyError::ImkeyTsmDeviceAuthenticityCheckFail.into())
            }
            constants::TSM_RETURNCODE_DEVICE_ACTIVE_FAIL => {
                Err(ImkeyError::ImkeyTsmDeviceActiveFail.into())
            }
            constants::TSM_RETURNCODE_SEID_ILLEGAL => Err(ImkeyError::ImkeyTsmDeviceIllegal.into()),
            constants::TSM_RETURNCODE_SE_QUERY_FAIL => {
                Err(ImkeyError::ImkeyTsmDeviceUpdateCheckFail.into())
            }
            constants::TSM_RETURNCODE_COS_VERSION_UNSUPPORT_APPLET => {
                Err(ImkeyError::ImkeyTsmCosVersionUnsupportApplet.into())
            }
            constants::TSM_RETURNCODE_DEVICE_UNSUPPORT_APPLET => {
                Err(ImkeyError::ImkeyTsmDeviceUnsupportApplet.into())
            }
            _ => Err(ImkeyError::ImkeyTsmServerError.into()),
        }
    }

    pub fn apdu_handle(apdu_list: Vec<String>) -> Result<(Vec<String>, String)> {
        let mut apdu_res: Vec<String> = vec![];
        let mut status_word: String = String::new();
        for (index_val, apdu_val) in apdu_list.iter().enumerate() {
            //sende apdu command
            let res = message::send_apdu(apdu_val.to_string())?;
            apdu_res.push(res.clone());
            if index_val == apdu_list.len() - 1 {
                let status_start = res
                    .len()
                    .checked_sub(4)
                    .ok_or(ApduError::ImkeyApduWrongLength)?;
                status_word = res
                    .get(status_start..)
                    .ok_or(ApduError::ImkeyApduWrongLength)?
                    .to_string();
            }
        }
        Ok((apdu_res, status_word))
    }
}

#[cfg(test)]
mod tests {
    use crate::app_download::AppDownloadResponse;
    use crate::ServiceResponse;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    fn apdu_handle_test() {
        assert!(hid_connect("imKey Pro").is_ok());
        let apdu_list = vec![
            "00a4040000".to_string(),
            "00a404000600000000000100".to_string(),
        ];
        assert!(ServiceResponse::<AppDownloadResponse>::apdu_handle(apdu_list).is_ok());
    }
}
