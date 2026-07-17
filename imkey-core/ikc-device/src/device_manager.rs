use super::app_update;
use super::se_activate;
use super::se_query::SeQueryRequest;
use super::se_secure_check::SeSecureCheckRequest;
use crate::app_delete::AppDeleteRequest;
use crate::app_download::{AppDownloadRequest, AppDownloadResponse};
use crate::app_update::AppUpdateResponse;
use crate::cos_check_update::{CosCheckUpdateRequest, CosCheckUpdateResponse};
use crate::cos_upgrade::CosUpgradeRequest;
use crate::device_binding::DeviceManage;
use crate::se_query::SeQueryResponse;
use crate::ServiceResponse;
use crate::{Result, TsmService};
use anyhow::anyhow;
use app_update::AppUpdateRequest;
use ikc_common::apdu::{Apdu, ApduCheck};
use ikc_common::applet;
use ikc_common::constants;
use ikc_common::error::ApduError;
use ikc_transport::message::send_apdu;
use regex::Regex;
use se_activate::SeActivateRequest;

pub fn select_isd() -> Result<String> {
    let res = send_apdu("00A4040000".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    Ok(res)
}

pub(crate) fn apdu_payload(response: &str) -> Result<&str> {
    let payload_end = response
        .len()
        .checked_sub(4)
        .ok_or(ApduError::ImkeyApduWrongLength)?;
    response
        .get(..payload_end)
        .ok_or_else(|| ApduError::ImkeyApduWrongLength.into())
}

pub(crate) fn apdu_status_word(response: &str) -> Result<&str> {
    let status_start = response
        .len()
        .checked_sub(4)
        .ok_or(ApduError::ImkeyApduWrongLength)?;
    response
        .get(status_start..)
        .ok_or_else(|| ApduError::ImkeyApduWrongLength.into())
}

pub fn get_se_id() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CB800005DFFF028101".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    Ok(apdu_payload(&res)?.to_string())
}

pub fn get_sn() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CA004400".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let sn = hex::decode(apdu_payload(&res)?)?;
    Ok(String::from_utf8(sn)?)
}

pub fn get_ram_size() -> Result<String> {
    let res = send_apdu("80CB800005DFFF02814600".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let hex_ram_size = res.get(4..8).ok_or(ApduError::ImkeyApduWrongLength)?;
    let ram_size = i64::from_str_radix(hex_ram_size, 16)?;
    Ok(ram_size.to_string())
}

pub fn get_firmware_version() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CB800005DFFF02800300".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let payload = apdu_payload(&res)?;
    let firmware_version = format!(
        "{}.{}.{}",
        payload.get(0..1).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(1..2).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(2..).ok_or(ApduError::ImkeyApduWrongLength)?
    );
    Ok(firmware_version)
}

pub fn get_bl_version() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CA800900".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let payload = apdu_payload(&res)?;
    let bl_version = format!(
        "{}.{}.{}",
        payload.get(0..1).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(1..2).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(2..).ok_or(ApduError::ImkeyApduWrongLength)?
    );
    Ok(bl_version)
}

pub fn get_battery_power() -> Result<String> {
    select_isd()?;
    let res = send_apdu("00D6FEED01".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let hex_power = apdu_payload(&res)?.to_string();
    let charging_flag = "FF";
    let power = match hex_power == charging_flag {
        true => hex_power,
        false => i64::from_str_radix(&hex_power, 16)?.to_string(),
    };
    Ok(power)
}

pub fn get_life_time() -> Result<String> {
    let res = send_apdu("FFDCFEED00".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let hex_life_time = apdu_payload(&res)?;
    let life_time = match hex_life_time {
        "80" => "life_time_device_inited",
        "89" => "life_time_device_activated",
        "81" => "life_time_unset_pin",
        "83" => "life_time_wallet_unready",
        "84" => "life_time_wallet_creatting",
        "85" => "life_time_wallet_recovering",
        "86" => "life_time_wallet_ready",
        _ => "life_time_unknown",
    };
    Ok(life_time.to_string())
}

pub fn get_ble_name() -> Result<String> {
    let res = send_apdu("FFDB465400".to_string())?;
    let hex = hex::decode(apdu_payload(&res)?)?;
    Ok(String::from_utf8(hex)?)
}

pub fn set_ble_name(ble_name: String) -> Result<String> {
    let name_verify_regex = Regex::new(r"[0-9A-Za-z]{1,12}")?;
    if !name_verify_regex.is_match(ble_name.as_ref()) {
        return Err(anyhow!("imkey_device_name_invalid"));
    }
    let apdu = Apdu::set_ble_name(ble_name.as_ref());
    let res = send_apdu(apdu)?;
    Ok(apdu_payload(&res)?.to_string())
}

pub fn get_ble_version() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CB800005DFFF02810000".to_string())?;
    let payload = apdu_payload(&res)?;
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 4 {
        return Err(ApduError::ImkeyApduWrongLength.into());
    }
    let format_version = format!("{}.{}.{}{}", chars[0], chars[1], chars[2], chars[3]);
    Ok(format_version)
}

pub fn get_cert() -> Result<String> {
    select_isd()?;
    let res = send_apdu("80CABF2106A6048302151800".to_string())?;
    ApduCheck::check_response(&res)?;
    Ok(apdu_payload(&res)?.to_string())
}

pub fn check_device() -> Result<()> {
    let seid: String = get_se_id()?;
    let sn: String = get_sn()?;
    let device_cert: String = get_cert()?;
    SeSecureCheckRequest::build_request_data(seid, sn, device_cert).send_message()
}

pub fn active_device() -> Result<()> {
    let seid: String = get_se_id()?;
    let sn: String = get_sn()?;
    let device_cert: String = get_cert()?;
    SeActivateRequest::build_request_data(seid, sn, device_cert).send_message()
}

pub fn check_update() -> Result<ServiceResponse<SeQueryResponse>> {
    let seid: String = get_se_id()?;
    let sn: String = get_sn()?;
    let sdk_version = Some(constants::VERSION.to_string());
    SeQueryRequest::build_request_data(seid, sn, sdk_version).send_message()
}

pub fn app_download(app_name: &str) -> Result<ServiceResponse<AppDownloadResponse>> {
    let seid: String = get_se_id()?;
    let device_cert: String = get_cert()?;
    let sdk_version = Some(constants::VERSION.to_string());
    let instance_aid: String = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    AppDownloadRequest::build_request_data(seid, instance_aid, device_cert, sdk_version)
        .send_message()
}

pub fn app_update(app_name: &str) -> Result<ServiceResponse<AppUpdateResponse>> {
    let seid: String = get_se_id()?;
    let device_cert: String = get_cert()?;
    let sdk_version = Some(constants::VERSION.to_string());
    let instance_aid: String = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    AppUpdateRequest::build_request_data(seid, instance_aid, device_cert, sdk_version)
        .send_message()
}

pub fn app_delete(app_name: &str) -> Result<()> {
    let seid: String = get_se_id()?;
    let device_cert: String = get_cert()?;
    let instance_aid: String = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    AppDeleteRequest::build_request_data(seid, instance_aid, device_cert).send_message()
}

pub fn bind_check(file_path: &str) -> Result<String> {
    DeviceManage::bind_check(file_path)
}

pub fn bind_display_code() -> Result<()> {
    DeviceManage::display_bind_code()
}

pub fn bind_acquire(bind_code: &str) -> Result<String> {
    DeviceManage::bind_acquire(bind_code)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn cos_upgrade() -> Result<()> {
    CosUpgradeRequest::cos_upgrade(None)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn cos_check_update() -> Result<ServiceResponse<CosCheckUpdateResponse>> {
    let seid = get_se_id()?;
    let cos_version = get_firmware_version()?;
    CosCheckUpdateRequest::build_request_data(seid, cos_version).send_message()
}
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn is_bl_status() -> Result<bool> {
    let res_data = send_apdu(Apdu::select_applet(constants::BL_AID)?)?;
    let check_result = ApduCheck::check_response(res_data.as_str());
    if check_result.is_err() {
        return Ok(false);
    }
    Ok(true)
}

pub fn get_btc_apple_version() -> Result<String> {
    select_isd()?;
    let res = send_apdu("00a4040005695f62746300".to_string())?;
    ApduCheck::check_response(res.as_str())?;
    let btc_version = hex::decode(apdu_payload(&res)?)?;
    let btc_version = String::from_utf8(btc_version)?;
    Ok(btc_version)
}

#[cfg(test)]
mod test {
    use crate::device_manager::{
        active_device, app_delete, app_download, app_update, bind_check, get_btc_apple_version,
        is_bl_status,
    };
    use ikc_common::constants;
    use ikc_transport::hid_api::hid_connect;

    #[test]
    fn is_bl_status_test() {
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = is_bl_status();
        assert!(result.is_ok());
    }

    #[test]
    fn app_delete_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = app_delete("Cosmos");
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "imkey_app_name_not_exist")]
    fn app_delete_wrong_app_name_test() {
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let _ = app_delete("TEST");
    }

    #[test]
    fn app_download_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = app_download("Cosmos");
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "imkey_app_name_not_exist")]
    fn app_download_wrong_appname_test() {
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        //Enter the wrong app name
        let _result = app_download("TEST");
    }

    #[test]
    fn app_update_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = app_update("Cosmos");
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "imkey_app_name_not_exist")]
    fn app_update_wrong_app_name_test() {
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let _result = app_update("TEST");
    }

    #[test]
    #[should_panic(expected = "No such file or directory")]
    fn bind_check_wrong_path_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = bind_check("/test/");
        assert!(result.is_ok());
    }

    #[test]
    fn active_device_test() {
        crate::configure_test_tsm_from_env();
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = active_device();
        assert!(result.is_ok());
    }

    #[test]
    fn get_btc_version_test() {
        assert!(hid_connect(constants::DEVICE_MODEL_NAME).is_ok());
        let result = get_btc_apple_version();
        assert!(result.is_ok());
    }
}
