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
pub mod cos_upgrade;
pub mod device_manager;
pub mod deviceapi;
pub mod key_manager;
#[macro_use]
extern crate lazy_static;
extern crate ikc_transport;
pub mod error;
#[macro_use]
extern crate failure;
use core::result;
pub type Result<T> = result::Result<T, failure::Error>;
use crate::error::ImkeyError;
use ikc_common::constants;
use ikc_transport::message;
use serde::{Deserialize, Serialize};

pub mod cos_check_update;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceResponse<T> {
    pub _ReturnCode: String,
    pub _ReturnMsg: String,
    pub _ReturnData: T,
}

pub trait TsmService {
    type ReturnData;
    fn send_message(&mut self) -> Result<Self::ReturnData>;
}

impl<T> ServiceResponse<T> {
    pub fn service_res_check(&self) -> Result<()> {
        match self._ReturnCode.as_str() {
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
                Err(ImkeyError::ImkeyTsmCosVersionUnsupport_applet.into())
            }
            constants::TSM_RETURNCODE_DEVICE_UNSUPPORT_APPLET => {
                Err(ImkeyError::ImkeyTsmDeviceUnsupport_applet.into())
            }
            _ => Err(ImkeyError::ImkeyTsmServerError.into()),
        }
    }

    pub fn apdu_handle(apdu_list: Vec<String>) -> Result<(Vec<String>, String)> {
        if apdu_list.is_empty() {
            ()
        }
        let mut apdu_res: Vec<String> = vec![];
        let mut status_word: String = String::new();
        for (index_val, apdu_val) in apdu_list.iter().enumerate() {
            //sende apdu command
            let res = message::send_apdu(apdu_val.to_string())?;
            apdu_res.push(res.clone());
            if index_val == apdu_list.len() - 1 {
                status_word = String::from(&res[res.len() - 4..]);
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
