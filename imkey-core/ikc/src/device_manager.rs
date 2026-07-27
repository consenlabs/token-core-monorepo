use crate::api::{CommonResponse, ConfigureTsmParam, InitImKeyCoreXParam};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use anyhow::anyhow;
use ikc_common::applet;
use ikc_common::constants;
use ikc_common::{OPERATING_SYSTEM, XPUB_COMMON_IV, XPUB_COMMON_KEY_128};
use ikc_device::device_manager;
use ikc_device::deviceapi::{
    AppDeleteReq, AppDownloadReq, AppDownloadRes, AppUpdateReq, AppUpdateRes, AvailableAppBean,
    BindAcquireReq, BindAcquireRes, BindCheckRes, CheckUpdateRes, CosCheckUpdateRes,
    DeviceConnectReq, GetBatteryPowerRes, GetBleNameRes, GetBleVersionRes, GetFirmwareVersionRes,
    GetLifeTimeRes, GetRamSizeRes, GetSdkInfoRes, GetSeidRes, GetSnRes, IsBlStatusRes,
    SetBleNameReq,
};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ikc_transport::hid_api::hid_connect;
use parking_lot::RwLock;
use prost::Message;

lazy_static! {
    pub static ref IS_DEBUG: RwLock<bool> = RwLock::new(false);
    pub static ref WALLET_FILE_DIR: RwLock<String> = RwLock::new("../test-data".to_string());
}

fn decode_message<T>(data: &[u8], error: &'static str) -> Result<T>
where
    T: Message + Default,
{
    T::decode(data).map_err(|_| anyhow!(error))
}

fn app_names_from_instance_aids(instance_aids: Option<Vec<String>>) -> Result<Vec<String>> {
    instance_aids
        .unwrap_or_default()
        .into_iter()
        .map(|instance_aid| {
            applet::get_appname_by_instid(instance_aid.as_str())
                .map(str::to_string)
                .ok_or_else(|| anyhow!("imKey_app_id_noe_exist"))
        })
        .collect()
}

fn required_string(value: Option<String>) -> Result<String> {
    value.ok_or_else(|| anyhow!("imkey_tsm_server_error"))
}

pub fn init_imkey_core(data: &[u8]) -> Result<Vec<u8>> {
    let InitImKeyCoreXParam {
        file_dir,
        xpub_common_key,
        xpub_common_iv,
        is_debug,
        system,
    } = decode_message::<InitImKeyCoreXParam>(data, "imkey_illegal_param")?;
    *WALLET_FILE_DIR.write() = file_dir.to_string();
    *XPUB_COMMON_KEY_128.write() = xpub_common_key.to_string();
    *XPUB_COMMON_IV.write() = xpub_common_iv.to_string();
    *IS_DEBUG.write() = is_debug;
    *OPERATING_SYSTEM.write() = system;
    Ok(vec![])
}

pub fn configure_tsm(data: &[u8]) -> Result<Vec<u8>> {
    let request = decode_message::<ConfigureTsmParam>(data, "imkey_illegal_param")?;
    ikc_common::tsm::configure_tsm_url(&request.base_url)?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn app_download(data: &[u8]) -> Result<Vec<u8>> {
    let request: AppDownloadReq = decode_message(data, "imkey_illegal_param")?;
    let response = device_manager::app_download(request.app_name.as_ref())?;

    let app_download_res = AppDownloadRes {
        address_register_list: app_names_from_instance_aids(
            response.return_data.address_register_list,
        )?,
    };

    encode_message(app_download_res)
}

pub fn app_update(data: &[u8]) -> Result<Vec<u8>> {
    let request: AppUpdateReq = decode_message(data, "imkey_illegal_prarm")?;
    let response = device_manager::app_update(request.app_name.as_ref())?;
    let app_update_res = AppUpdateRes {
        address_register_list: app_names_from_instance_aids(
            response.return_data.address_register_list,
        )?,
    };

    encode_message(app_update_res)
}

pub fn app_delete(data: &[u8]) -> Result<Vec<u8>> {
    let request: AppDeleteReq = decode_message(data, "imkey_illegal_param")?;
    device_manager::app_delete(request.app_name.as_ref())?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn se_activate() -> Result<Vec<u8>> {
    device_manager::active_device()?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn check_update() -> Result<Vec<u8>> {
    let response = device_manager::check_update()?;

    let mut available_bean_list: Vec<AvailableAppBean> = Vec::new();
    for value in response
        .return_data
        .available_app_bean_list
        .unwrap_or_default()
    {
        let version = match value.installed_version.as_ref() {
            Some(version) => version,
            None => "none",
        };
        let Some(instance_aid) = value.instance_aid.as_ref() else {
            continue;
        };
        let app_name = applet::get_appname_by_instid(instance_aid);
        if app_name.is_none() {
            continue;
        }

        available_bean_list.push(AvailableAppBean {
            app_name: app_name.unwrap_or_default().to_string(),
            app_logo: value.app_logo.unwrap_or_default(),
            installed_version: version.to_string(),
            last_updated: value.last_updated.unwrap_or_default(),
            latest_version: value.latest_version.unwrap_or_default(),
            install_mode: value.install_mode.unwrap_or_default(),
        });
    }

    let return_code = response.return_code;
    let mut status = constants::IMKEY_DEV_STATUS_LATEST;
    if return_code == constants::TSM_RETURNCODE_DEV_INACTIVATED {
        status = constants::IMKEY_DEV_STATUS_INACTIVATED;
    }

    let response_msg = CheckUpdateRes {
        se_id: required_string(response.return_data.seid)?,
        sn: required_string(response.return_data.sn)?,
        status: status.to_string(),
        sdk_mode: required_string(response.return_data.sdk_mode)?,
        available_app_list: available_bean_list,
    };
    encode_message(response_msg)
}

pub fn se_secure_check() -> Result<Vec<u8>> {
    device_manager::check_device()?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn bind_check() -> Result<Vec<u8>> {
    let file_path = WALLET_FILE_DIR.read();
    let check_result = device_manager::bind_check(file_path.as_str())?;
    let response_msg = BindCheckRes {
        bind_status: check_result,
    };
    encode_message(response_msg)
}

pub fn bind_display_code() -> Result<Vec<u8>> {
    device_manager::bind_display_code()?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn bind_acquire(data: &[u8]) -> Result<Vec<u8>> {
    let bind_acquire: BindAcquireReq = decode_message(data, "imkey_illegal_param")?;
    let bind_result = device_manager::bind_acquire(&bind_acquire.bind_code)?;
    let response_msg = BindAcquireRes { bind_result };
    encode_message(response_msg)
}

pub fn get_seid() -> Result<Vec<u8>> {
    let seid = device_manager::get_se_id().map_err(|_| anyhow!("get_seid_error"))?;
    let response_msg = GetSeidRes { seid };
    encode_message(response_msg)
}

pub fn get_sn() -> Result<Vec<u8>> {
    let sn = device_manager::get_sn().map_err(|_| anyhow!("get_sn_error"))?;
    let response_msg = GetSnRes { sn };
    encode_message(response_msg)
}

pub fn get_ram_size() -> Result<Vec<u8>> {
    let ram_size = device_manager::get_ram_size().map_err(|_| anyhow!("get_ram_size_error"))?;
    let response_msg = GetRamSizeRes { ram_size };
    encode_message(response_msg)
}

pub fn get_firmware_version() -> Result<Vec<u8>> {
    let firmware_version = device_manager::get_firmware_version()
        .map_err(|_| anyhow!("get_firmware_version_error"))?;

    let response_msg = GetFirmwareVersionRes { firmware_version };
    encode_message(response_msg)
}

pub fn get_battery_power() -> Result<Vec<u8>> {
    let battery_power =
        device_manager::get_battery_power().map_err(|_| anyhow!("get_battery_power_error"))?;
    let response_msg = GetBatteryPowerRes { battery_power };
    encode_message(response_msg)
}

pub fn get_life_time() -> Result<Vec<u8>> {
    let life_time = device_manager::get_life_time().map_err(|_| anyhow!("get_life_time_error"))?;
    let response_msg = GetLifeTimeRes { life_time };
    encode_message(response_msg)
}

pub fn get_ble_name() -> Result<Vec<u8>> {
    let ble_name = device_manager::get_ble_name().map_err(|_| anyhow!("get_ble_name_error"))?;

    let response_msg = GetBleNameRes { ble_name };
    encode_message(response_msg)
}

pub fn set_ble_name(data: &[u8]) -> Result<Vec<u8>> {
    let request: SetBleNameReq = decode_message(data, "ble_action")?;

    device_manager::set_ble_name(request.ble_name).map_err(|_| anyhow!("set_ble_name_error"))?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

pub fn get_ble_version() -> Result<Vec<u8>> {
    let ble_version =
        device_manager::get_ble_version().map_err(|_| anyhow!("get_ble_version_error"))?;
    let response_msg = GetBleVersionRes { ble_version };
    encode_message(response_msg)
}

pub fn get_sdk_info() -> Result<Vec<u8>> {
    let response_msg = GetSdkInfoRes {
        sdk_version: constants::VERSION.to_string(),
    };
    encode_message(response_msg)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn cos_update() -> Result<Vec<u8>> {
    device_manager::cos_upgrade()?;
    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn device_connect(data: &[u8]) -> Result<Vec<u8>> {
    let device_connect_req: DeviceConnectReq = decode_message(data, "imkey_illegal_param")?;

    hid_connect(&device_connect_req.device_model_name)?;

    encode_message(CommonResponse {
        result: "success".to_string(),
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn cos_check_update() -> Result<Vec<u8>> {
    let cos_check_update = device_manager::cos_check_update()?;

    encode_message(CosCheckUpdateRes {
        seid: cos_check_update.return_data.seid,
        is_latest: cos_check_update.return_data.is_latest,
        latest_cos_version: cos_check_update
            .return_data
            .latest_cos_version
            .unwrap_or_default(),
        update_type: cos_check_update.return_data.update_type.unwrap_or_default(),
        description: cos_check_update.return_data.description.unwrap_or_default(),
        is_update_success: cos_check_update.return_data.is_update_success,
        latest_ble_version: cos_check_update
            .return_data
            .latest_ble_version
            .unwrap_or_default(),
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn is_bl_status() -> Result<Vec<u8>> {
    let check_result = device_manager::is_bl_status()?;
    encode_message(IsBlStatusRes { check_result })
}

#[cfg(test)]
mod tests {
    use super::{app_delete, init_imkey_core, set_ble_name};

    #[test]
    fn invalid_device_api_params_return_compat_errors() {
        assert_eq!(
            "imkey_illegal_param",
            app_delete(&[0xff]).unwrap_err().to_string()
        );
        assert_eq!(
            "imkey_illegal_param",
            init_imkey_core(&[0xff]).unwrap_err().to_string()
        );
        assert_eq!("ble_action", set_ble_name(&[0xff]).unwrap_err().to_string());
    }
}
