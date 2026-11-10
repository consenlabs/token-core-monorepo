use crate::app_delete::AppDeleteRequest;
use crate::app_download::{AppDownloadRequest, AppDownloadResponse};
use crate::app_update::{AppUpdateRequest, AppUpdateResponse};
use crate::auth_code_storage::{AuthCodeStorageRequest, AuthCodeStorageResponse};
use crate::ble_upgrade::{BleUpgradeRequest, BleUpgradeResponse};
use crate::cos_check_update::{CosCheckUpdateRequest, CosCheckUpdateResponse};
use crate::cos_upgrade::{CosUpgradeRequest, CosUpgradeResponse};
use crate::device_binding::{
    auth_code_encrypt, bind_status_message, gen_iv, get_se_pubkey, KEY_MANAGER,
};
use crate::device_cert_check::{DeviceCertCheckRequest, DeviceCertCheckResponse};
use crate::error::{BindError, ImkeyError};
use crate::se_activate::SeActivateRequest;
use crate::se_query::{SeQueryRequest, SeQueryResponse};
use crate::se_secure_check::SeSecureCheckRequest;
use crate::{Result, ServiceResponse, TsmStepRequest, TsmStepResponse};
use anyhow::anyhow;
use ikc_common::aes::cbc::encrypt_pkcs7;
use ikc_common::apdu::{Apdu, ApduCheck, ImkApdu};
use ikc_common::applet;
use ikc_common::constants::{
    self, BIND_RESULT_ERROR, BIND_STATUS_BOUND_OTHER, BIND_STATUS_UNBOUND, TIMEOUT_LONG,
};
use ikc_common::error::ApduError;
use ikc_common::utility::{hex_to_bytes, sha256_hash};
pub use ikc_transport::async_transport::{
    AsyncApduTransport, AsyncReconnectableTransport, BoxFutureResult, TransportProfile,
};
use regex::Regex;
use secp256k1::{ecdh, PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha1::Digest;
use std::convert::{TryFrom, TryInto};

const FIRMWARE_RECONNECT_TIMEOUT: i32 = 30;

pub trait AsyncTsmClient {
    fn post<'a>(&'a self, action: &'a str, body: Vec<u8>) -> BoxFutureResult<'a, String>;
}

pub trait AsyncBindingStorage {
    fn load<'a>(&'a self, seid: &'a str) -> BoxFutureResult<'a, Option<String>>;
    fn save<'a>(&'a self, seid: &'a str, encrypted_key: &'a str) -> BoxFutureResult<'a, ()>;
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub seid: String,
    pub sn: String,
    pub firmware_version: String,
    pub life_time: String,
}

async fn send_checked<T>(transport: &T, apdu: &str) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    send_checked_timeout(transport, apdu, 20).await
}

async fn send_checked_timeout<T>(transport: &T, apdu: &str, timeout: i32) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    let response = transport.send_apdu(apdu, timeout).await?;
    ApduCheck::check_response(&response)?;
    Ok(response)
}

async fn select_isd<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    send_checked(transport, "00A4040000").await
}

async fn select_imk<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    let apdu = Apdu::select_applet(constants::IMK_AID)?;
    send_checked(transport, &apdu).await
}

fn apdu_payload(response: &str) -> Result<&str> {
    let payload_end = response
        .len()
        .checked_sub(4)
        .ok_or(ApduError::ImkeyApduWrongLength)?;
    response
        .get(..payload_end)
        .ok_or_else(|| ApduError::ImkeyApduWrongLength.into())
}

fn apdu_status_word(response: &str) -> Result<&str> {
    let status_start = response
        .len()
        .checked_sub(4)
        .ok_or(ApduError::ImkeyApduWrongLength)?;
    response
        .get(status_start..)
        .ok_or_else(|| ApduError::ImkeyApduWrongLength.into())
}

fn map_web_life_time(value: &str) -> &'static str {
    match value {
        "00" => "device_unactivated",
        "01" => "device_activated",
        _ => "unknown",
    }
}

fn map_legacy_life_time(value: &str) -> &'static str {
    match value {
        "80" => "life_time_device_inited",
        "89" => "life_time_device_activated",
        "81" => "life_time_unset_pin",
        "83" => "life_time_wallet_unready",
        "84" => "life_time_wallet_creatting",
        "85" => "life_time_wallet_recovering",
        "86" => "life_time_wallet_ready",
        _ => "life_time_unknown",
    }
}

pub async fn get_se_id<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CB800005DFFF028101").await?;
    Ok(apdu_payload(&response)?.to_string())
}

pub async fn get_sn<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CA004400").await?;
    let sn = hex::decode(apdu_payload(&response)?)?;
    Ok(String::from_utf8(sn)?)
}

pub async fn get_ram_size<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CB800005DFFF02814600").await?;
    let hex_ram_size = response.get(4..8).ok_or(ApduError::ImkeyApduWrongLength)?;
    Ok(i64::from_str_radix(hex_ram_size, 16)?.to_string())
}

pub async fn get_firmware_version<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CB800005DFFF02800300").await?;
    let payload = apdu_payload(&response)?;
    let firmware_version = format!(
        "{}.{}.{}",
        payload.get(0..1).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(1..2).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(2..).ok_or(ApduError::ImkeyApduWrongLength)?
    );
    Ok(firmware_version)
}

pub async fn get_bl_version<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CA800900").await?;
    let payload = apdu_payload(&response)?;
    Ok(format!(
        "{}.{}.{}",
        payload.get(0..1).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(1..2).ok_or(ApduError::ImkeyApduWrongLength)?,
        payload.get(2..).ok_or(ApduError::ImkeyApduWrongLength)?
    ))
}

pub fn get_sdk_info() -> String {
    constants::VERSION.to_string()
}

pub async fn get_battery_power<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "00D6FEED01").await?;
    let hex_power = apdu_payload(&response)?.to_string();
    if hex_power == "FF" {
        Ok(hex_power)
    } else {
        Ok(i64::from_str_radix(&hex_power, 16)?.to_string())
    }
}

pub async fn get_ble_name<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    let response = send_checked(transport, "FFDB465400").await?;
    let hex = hex::decode(apdu_payload(&response)?)?;
    Ok(String::from_utf8(hex)?)
}

pub async fn set_ble_name<T>(transport: &T, ble_name: &str) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    let name_verify_regex = Regex::new(r"^[0-9A-Za-z]{1,12}$")?;
    if !name_verify_regex.is_match(ble_name) {
        return Err(anyhow!("imkey_device_name_invalid"));
    }
    let response = send_checked(transport, &Apdu::set_ble_name(ble_name)).await?;
    Ok(apdu_payload(&response)?.to_string())
}

pub async fn get_ble_version<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CB800005DFFF02810000").await?;
    let payload = apdu_payload(&response)?;
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 4 {
        return Err(ApduError::ImkeyApduWrongLength.into());
    }
    Ok(format!(
        "{}.{}.{}{}",
        chars[0], chars[1], chars[2], chars[3]
    ))
}

pub async fn get_life_time<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    match transport.profile() {
        TransportProfile::WebUsb | TransportProfile::WebHid => {
            select_isd(transport).await?;
            let response = send_checked(transport, "80CB800005DFFF02814700").await?;
            Ok(map_web_life_time(apdu_payload(&response)?).to_string())
        }
        TransportProfile::Ble | TransportProfile::NativeHid => {
            let response = send_checked(transport, "FFDCFEED00").await?;
            Ok(map_legacy_life_time(apdu_payload(&response)?).to_string())
        }
    }
}

pub async fn get_cert<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "80CABF2106A6048302151800").await?;
    Ok(apdu_payload(&response)?.to_string())
}

pub async fn get_btc_apple_version<T>(transport: &T) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
{
    select_isd(transport).await?;
    let response = send_checked(transport, "00a4040005695f62746300").await?;
    let btc_version = hex::decode(apdu_payload(&response)?)?;
    Ok(String::from_utf8(btc_version)?)
}

pub async fn get_device_info<T>(transport: &T) -> Result<DeviceInfo>
where
    T: AsyncApduTransport + ?Sized,
{
    Ok(DeviceInfo {
        seid: get_se_id(transport).await?,
        sn: get_sn(transport).await?,
        firmware_version: get_firmware_version(transport).await?,
        life_time: get_life_time(transport).await?,
    })
}

pub async fn bind_display_code<T>(transport: &T) -> Result<()>
where
    T: AsyncApduTransport + ?Sized,
{
    select_imk(transport).await?;
    send_checked(transport, &ImkApdu::generate_auth_code()).await?;
    Ok(())
}

async fn device_cert_check<C>(
    tsm_client: &C,
    seid: String,
    sn: String,
    device_cert: String,
) -> Result<()>
where
    C: AsyncTsmClient + ?Sized,
{
    let request = DeviceCertCheckRequest::build_request_data(seid, sn, device_cert);
    let req_data = serde_json::to_vec_pretty(&request)?;
    let response_data = tsm_client
        .post(constants::TSM_ACTION_DEVICE_CERT_CHECK, req_data)
        .await?;
    let return_bean: ServiceResponse<DeviceCertCheckResponse> =
        serde_json::from_str(&response_data)?;

    return_bean.service_res_check()?;
    if return_bean.return_data.verify_result.unwrap_or(false) {
        Ok(())
    } else {
        Err(ImkeyError::ImkeySeCertInvalid.into())
    }
}

async fn auth_code_storage<C>(tsm_client: &C, seid: String, auth_code: String) -> Result<()>
where
    C: AsyncTsmClient + ?Sized,
{
    let request = AuthCodeStorageRequest::build_request_data(seid, auth_code);
    let req_data = serde_json::to_vec_pretty(&request)?;
    let response_data = tsm_client
        .post(constants::TSM_ACTION_AUTHCODE_STORAGE, req_data)
        .await?;
    let return_bean: ServiceResponse<AuthCodeStorageResponse> =
        serde_json::from_str(&response_data)?;
    return_bean.service_res_check()
}

pub async fn bind_check<T, C, S>(transport: &T, tsm_client: &C, storage: &S) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
    S: AsyncBindingStorage + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let sn = get_sn(transport).await?;
    {
        let mut key_manager = KEY_MANAGER.lock();
        key_manager.gen_encrypt_key(&seid, &sn);
    }

    let ciphertext = storage.load(&seid).await?.unwrap_or_default();
    let (bind_check_apdu, should_save_new_keys) = {
        let mut key_manager = KEY_MANAGER.lock();
        let mut should_regenerate = false;
        if !ciphertext.is_empty() {
            should_regenerate = !key_manager.decrypt_keys(&ciphertext)?;
        }

        if ciphertext.is_empty() || should_regenerate {
            key_manager.gen_local_keys()?;
            should_regenerate = true;
        }

        (
            ImkApdu::bind_check(&key_manager.pub_key)?,
            should_regenerate,
        )
    };

    select_imk(transport).await?;
    let bind_check_response = send_checked(transport, &bind_check_apdu).await?;
    let payload_end = bind_check_response
        .len()
        .checked_sub(4)
        .ok_or(BindError::ImkeySdkIllegalArgument)?;
    let status = bind_check_response
        .get(..2)
        .ok_or(BindError::ImkeySdkIllegalArgument)?
        .to_string();
    let se_pub_key_cert = bind_check_response
        .get(2..payload_end)
        .ok_or(BindError::ImkeySdkIllegalArgument)?
        .to_string();

    if status == BIND_STATUS_UNBOUND || status == BIND_STATUS_BOUND_OTHER {
        device_cert_check(tsm_client, seid.clone(), sn, se_pub_key_cert.clone()).await?;

        let se_pub_key = hex::decode(get_se_pubkey(&se_pub_key_cert)?)?;
        let encrypted_key = {
            let mut key_manager = KEY_MANAGER.lock();
            key_manager.se_pub_key = se_pub_key;
            let pk2 = PublicKey::from_slice(key_manager.se_pub_key.as_slice())?;
            let sk1 = SecretKey::from_byte_array(key_manager.pri_key.as_slice().try_into()?)?;
            let shared_secret = ecdh::shared_secret_point(&pk2, &sk1);
            let sha1_result = sha1::Sha1::digest(&shared_secret[..32]);
            key_manager.session_key = sha1_result[..16].to_vec();

            if should_save_new_keys {
                Some(key_manager.encrypt_data()?)
            } else {
                None
            }
        };

        if let Some(encrypted_key) = encrypted_key {
            storage.save(&seid, &encrypted_key).await?;
        }
    }

    bind_status_message(&status)
}

pub async fn bind_acquire<T, C>(transport: &T, tsm_client: &C, binding_code: &str) -> Result<String>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let temp_binding_code = binding_code.to_uppercase();
    let bind_code_verify_regex =
        Regex::new(r"^[A-HJ-NP-Z2-9]{8}$").map_err(|_| BindError::ImkeySdkIllegalArgument)?;
    if !bind_code_verify_regex.is_match(temp_binding_code.as_ref()) {
        return Err(BindError::ImkeySdkIllegalArgument.into());
    }

    let auth_code_ciphertext = auth_code_encrypt(&temp_binding_code)?;
    let seid = get_se_id(transport).await?;
    auth_code_storage(tsm_client, seid, auth_code_ciphertext).await?;

    let (pub_key, se_pub_key, session_key) = {
        let key_manager = KEY_MANAGER.lock();
        if key_manager.pub_key.is_empty()
            || key_manager.se_pub_key.is_empty()
            || key_manager.session_key.is_empty()
        {
            return Err(anyhow!("imkey_bind_check_required"));
        }
        (
            key_manager.pub_key.clone(),
            key_manager.se_pub_key.clone(),
            key_manager.session_key.clone(),
        )
    };

    select_imk(transport).await?;
    let mut data = Vec::new();
    data.extend(temp_binding_code.as_bytes());
    data.extend(&pub_key);
    data.extend(&se_pub_key);
    let data_hash = sha256_hash(data.as_slice());
    let ciphertext = encrypt_pkcs7(
        data_hash.as_ref(),
        &session_key,
        &gen_iv(&temp_binding_code),
    )?;
    let mut apdu_data = Vec::new();
    apdu_data.extend(&pub_key);
    apdu_data.extend(ciphertext);
    let identity_verify_apdu = ImkApdu::identity_verify(&apdu_data)?;

    let bind_result =
        send_checked_timeout(transport, &identity_verify_apdu, TIMEOUT_LONG * 2).await?;
    let result_code_end = bind_result
        .len()
        .checked_sub(4)
        .ok_or(BindError::ImkeySdkIllegalArgument)?;
    let result_code = bind_result
        .get(..result_code_end)
        .ok_or(BindError::ImkeySdkIllegalArgument)?;

    match result_code {
        BIND_RESULT_ERROR => Err(BindError::ImkeyAuthcodeError.into()),
        _ => bind_status_message(result_code),
    }
}

pub async fn run_tsm_steps<T, C, R>(
    request: &mut R,
    transport: &T,
    tsm_client: &C,
) -> Result<ServiceResponse<R::Response>>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
    R: TsmStepRequest,
    R::Response: DeserializeOwned + TsmStepResponse,
{
    loop {
        let req_data = serde_json::to_vec_pretty(request)?;
        let response_data = tsm_client.post(request.tsm_action(), req_data).await?;
        let return_bean: ServiceResponse<R::Response> = serde_json::from_str(&response_data)?;
        if return_bean.return_code != constants::TSM_RETURN_CODE_SUCCESS {
            return_bean.service_res_check()?;
            continue;
        }

        let next_step_key = return_bean
            .return_data
            .next_step_key()
            .ok_or(crate::error::ImkeyError::ImkeyTsmServerError)?
            .to_string();
        if constants::TSM_END_FLAG == next_step_key {
            return Ok(return_bean);
        }

        let apdu_list = return_bean
            .return_data
            .apdu_list()
            .ok_or(crate::error::ImkeyError::ImkeyTsmServerError)?
            .to_vec();
        let (card_ret_data_list, status_word) = apdu_handle(transport, apdu_list).await?;
        request.update_step_result(next_step_key, card_ret_data_list, status_word);
    }
}

pub async fn apdu_handle<T>(transport: &T, apdu_list: Vec<String>) -> Result<(Vec<String>, String)>
where
    T: AsyncApduTransport + ?Sized,
{
    let mut apdu_res = Vec::new();
    let mut status_word = String::new();
    for (index, apdu) in apdu_list.iter().enumerate() {
        let response = transport.send_apdu(apdu, 20).await?;
        if index == apdu_list.len() - 1 {
            status_word = apdu_status_word(&response)?.to_string();
        }
        apdu_res.push(response);
    }
    Ok((apdu_res, status_word))
}

pub async fn secure_check<T, C>(transport: &T, tsm_client: &C) -> Result<()>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let sn = get_sn(transport).await?;
    let device_cert = get_cert(transport).await?;
    let mut request = SeSecureCheckRequest::build_request_data(seid, sn, device_cert);
    run_tsm_steps(&mut request, transport, tsm_client)
        .await
        .map(|_| ())
}

pub async fn activate<T, C>(transport: &T, tsm_client: &C) -> Result<()>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let sn = get_sn(transport).await?;
    let device_cert = get_cert(transport).await?;
    let mut request = SeActivateRequest::build_request_data(seid, sn, device_cert);
    run_tsm_steps(&mut request, transport, tsm_client)
        .await
        .map(|_| ())
}

pub async fn check_update<T, C>(
    transport: &T,
    tsm_client: &C,
) -> Result<ServiceResponse<SeQueryResponse>>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let sn = get_sn(transport).await?;
    let request =
        SeQueryRequest::build_request_data(seid, sn, Some(constants::VERSION.to_string()));
    let req_data = serde_json::to_vec_pretty(&request)?;
    let response_data = tsm_client
        .post(constants::TSM_ACTION_SE_QUERY, req_data)
        .await?;
    let mut return_bean: ServiceResponse<SeQueryResponse> = serde_json::from_str(&response_data)?;
    match return_bean.service_res_check() {
        Ok(()) => {
            return_bean.return_data.status = Some(constants::IMKEY_DEV_STATUS_LATEST.to_string());
            Ok(return_bean)
        }
        Err(e) => {
            if constants::TSM_RETURNCODE_DEV_INACTIVATED == return_bean.return_code {
                return Ok(return_bean);
            }
            Err(e)
        }
    }
}

pub async fn app_download<T, C>(
    transport: &T,
    tsm_client: &C,
    app_name: &str,
) -> Result<ServiceResponse<AppDownloadResponse>>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let device_cert = get_cert(transport).await?;
    let instance_aid = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    let mut request = AppDownloadRequest::build_request_data(
        seid,
        instance_aid,
        device_cert,
        Some(constants::VERSION.to_string()),
    );
    run_tsm_steps(&mut request, transport, tsm_client).await
}

pub async fn app_update<T, C>(
    transport: &T,
    tsm_client: &C,
    app_name: &str,
) -> Result<ServiceResponse<AppUpdateResponse>>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let device_cert = get_cert(transport).await?;
    let instance_aid = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    let mut request = AppUpdateRequest::build_request_data(
        seid,
        instance_aid,
        device_cert,
        Some(constants::VERSION.to_string()),
    );
    run_tsm_steps(&mut request, transport, tsm_client).await
}

pub async fn app_delete<T, C>(transport: &T, tsm_client: &C, app_name: &str) -> Result<()>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let device_cert = get_cert(transport).await?;
    let instance_aid = applet::get_instid_by_appname(app_name)
        .ok_or_else(|| anyhow!("imkey_app_name_not_exist"))?
        .to_string();
    let mut request = AppDeleteRequest::build_request_data(seid, instance_aid, device_cert);
    run_tsm_steps(&mut request, transport, tsm_client)
        .await
        .map(|_| ())
}

pub async fn cos_check_update<T, C>(
    transport: &T,
    tsm_client: &C,
) -> Result<ServiceResponse<CosCheckUpdateResponse>>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let seid = get_se_id(transport).await?;
    let cos_version = get_firmware_version(transport).await?;
    let ble_version = get_ble_version(transport).await?;
    let request = CosCheckUpdateRequest::build_request_data(seid, cos_version, ble_version);
    let req_data = serde_json::to_vec_pretty(&request)?;
    let response_data = tsm_client
        .post(constants::TSM_ACTION_COS_CHECK_UPDATE, req_data)
        .await?;
    let return_bean: ServiceResponse<CosCheckUpdateResponse> =
        serde_json::from_str(&response_data)?;
    return_bean.service_res_check()?;
    Ok(return_bean)
}

async fn download_instance<T, C>(
    transport: &T,
    tsm_client: &C,
    seid: String,
    instance_aid: String,
    device_cert: String,
    sdk_version: Option<String>,
) -> Result<()>
where
    T: AsyncApduTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let mut request =
        AppDownloadRequest::build_request_data(seid, instance_aid, device_cert, sdk_version);
    run_tsm_steps(&mut request, transport, tsm_client)
        .await
        .map(|_| ())
}

pub async fn cos_upgrade<T, C>(transport: &T, tsm_client: &C) -> Result<()>
where
    T: AsyncReconnectableTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let mut device_cert = get_cert(transport).await?;
    let mut se_cos_version = String::new();
    let mut se_bl_version = None;
    let (seid, sn, is_bl_status, step_key) = if device_cert
        .get(..4)
        .is_some_and(|value| value.eq_ignore_ascii_case("bf21"))
    {
        se_cos_version = get_firmware_version(transport).await?;
        (
            get_se_id(transport).await?,
            get_sn(transport).await?,
            false,
            "01".to_string(),
        )
    } else if device_cert
        .get(..4)
        .is_some_and(|value| value.eq_ignore_ascii_case("7f21"))
    {
        let seid = device_cert
            .get(12..44)
            .ok_or(ImkeyError::ImkeyTsmCosUpgradeFail)?
            .to_string();
        let cert_length =
            u8::try_from(device_cert.len() / 2).map_err(|_| ImkeyError::ImkeyTsmCosUpgradeFail)?;
        let mut wrapped_cert = hex_to_bytes("bf2181")?;
        wrapped_cert.push(cert_length);
        wrapped_cert.extend(hex_to_bytes(&device_cert)?);
        device_cert = hex::encode_upper(wrapped_cert);
        se_bl_version = Some(get_bl_version(transport).await?);
        (seid, "0000000000000000".to_string(), true, "03".to_string())
    } else {
        return Err(ImkeyError::ImkeyTsmCosUpgradeFail.into());
    };

    let mut request = CosUpgradeRequest {
        seid: seid.clone(),
        sn,
        device_cert: device_cert.clone(),
        se_cos_version,
        is_bl_status,
        step_key,
        status_word: None,
        command_id: constants::TSM_ACTION_COS_UPGRADE.to_string(),
        card_ret_data_list: None,
        se_bl_version,
    };

    loop {
        let req_data = serde_json::to_vec_pretty(&request)?;
        let response_data = tsm_client
            .post(constants::TSM_ACTION_COS_UPGRADE, req_data)
            .await?;
        let return_bean: ServiceResponse<CosUpgradeResponse> =
            serde_json::from_str(&response_data)?;
        if return_bean.return_code != constants::TSM_RETURN_CODE_SUCCESS {
            return_bean.service_res_check()?;
            continue;
        }

        let next_step_key = return_bean
            .return_data
            .next_step_key
            .clone()
            .ok_or(ImkeyError::ImkeyTsmServerError)?;
        if next_step_key == constants::TSM_END_FLAG {
            return ble_upgrade(transport, tsm_client).await;
        }

        if let Some(apdu_list) = return_bean.return_data.apdu_list.clone() {
            let mut apdu_results = Vec::with_capacity(apdu_list.len());
            for (index, apdu) in apdu_list.iter().enumerate() {
                let response = transport.send_apdu(apdu, 20).await?;
                if index == apdu_list.len() - 1 {
                    let status_word = apdu_status_word(&response)?.to_uppercase();
                    request.status_word = Some(status_word.clone());
                    if status_word == constants::APDU_RSP_SUCCESS
                        || status_word == constants::APDU_RSP_SWITCH_BL_STATUS_SUCCESS
                    {
                        if next_step_key == "03" {
                            transport.reconnect(FIRMWARE_RECONNECT_TIMEOUT).await?;
                            request.se_bl_version = Some(get_bl_version(transport).await?);
                        } else if next_step_key == "05" {
                            transport.reconnect(FIRMWARE_RECONNECT_TIMEOUT).await?;
                            request.se_cos_version = get_firmware_version(transport).await?;
                        }
                    }
                }
                apdu_results.push(response);
            }
            request.card_ret_data_list = Some(apdu_results);
        }

        if next_step_key == "06" {
            if let Some(instance_aids) = return_bean.return_data.instance_aid_list.as_deref() {
                for instance_aid in instance_aids {
                    download_instance(
                        transport,
                        tsm_client,
                        seid.clone(),
                        instance_aid.clone(),
                        device_cert.clone(),
                        Some(constants::VERSION.to_string()),
                    )
                    .await?;
                }
            }
        }
        request.step_key = next_step_key;
    }
}

pub async fn ble_upgrade<T, C>(transport: &T, tsm_client: &C) -> Result<()>
where
    T: AsyncReconnectableTransport + ?Sized,
    C: AsyncTsmClient + ?Sized,
{
    let mut request = BleUpgradeRequest {
        seid: get_se_id(transport).await?,
        sn: get_sn(transport).await?,
        device_cert: get_cert(transport).await?,
        cos_version: get_firmware_version(transport).await?,
        ble_version: get_ble_version(transport).await?,
        step_key: "01".to_string(),
        status_word: None,
        command_id: constants::TSM_ACTION_BLE_UPDATE.to_string(),
        card_ret_data_list: None,
    };

    loop {
        let req_data = serde_json::to_vec_pretty(&request)?;
        let response_data = tsm_client
            .post(constants::TSM_ACTION_BLE_UPDATE, req_data)
            .await?;
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

        if let Some(apdu_list) = return_bean.return_data.apdu_list {
            let mut apdu_results = Vec::with_capacity(apdu_list.len());
            let mut last_status_word = None;
            for (index, apdu) in apdu_list.iter().enumerate() {
                let response = transport.send_apdu(apdu, 20).await?;
                let status_word = apdu_status_word(&response)?.to_uppercase();
                if next_step_key == "03" {
                    if index == 0 {
                        ApduCheck::check_response(&response)?;
                    } else if index == 5 && status_word == constants::APDU_RSP_APPLET_WRONG_DATA {
                        return Err(anyhow!("imkey_ble_upgrade_fail"));
                    }
                }
                last_status_word = Some(status_word);
                apdu_results.push(response);
            }

            if let Some(status_word) = last_status_word {
                request.status_word = Some(status_word.clone());
                if next_step_key == "03" && status_word == constants::APDU_RSP_SUCCESS {
                    transport.reconnect(FIRMWARE_RECONNECT_TIMEOUT).await?;
                    request.ble_version = get_ble_version(transport).await?;
                }
            }
            request.card_ret_data_list = Some(apdu_results);
        }
        request.step_key = next_step_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockTransport {
        responses: Mutex<VecDeque<String>>,
        reconnects: AtomicUsize,
    }

    impl MockTransport {
        fn new(responses: &[&str]) -> Self {
            Self {
                responses: Mutex::new(responses.iter().map(|value| value.to_string()).collect()),
                reconnects: AtomicUsize::new(0),
            }
        }

        fn assert_drained(&self) {
            assert!(self.responses.lock().is_empty());
        }
    }

    impl AsyncApduTransport for MockTransport {
        fn profile(&self) -> TransportProfile {
            TransportProfile::WebUsb
        }

        fn send_apdu<'a>(&'a self, _apdu: &'a str, _timeout: i32) -> BoxFutureResult<'a, String> {
            Box::pin(async move {
                self.responses
                    .lock()
                    .pop_front()
                    .ok_or_else(|| anyhow!("missing_mock_apdu_response"))
            })
        }
    }

    impl AsyncReconnectableTransport for MockTransport {
        fn reconnect<'a>(&'a self, _timeout: i32) -> BoxFutureResult<'a, ()> {
            Box::pin(async move {
                self.reconnects.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    struct MockTsmClient {
        responses: Mutex<VecDeque<String>>,
        requests: Mutex<Vec<(String, Value)>>,
    }

    impl MockTsmClient {
        fn new(responses: &[&str]) -> Self {
            Self {
                responses: Mutex::new(responses.iter().map(|value| value.to_string()).collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl AsyncTsmClient for MockTsmClient {
        fn post<'a>(&'a self, action: &'a str, body: Vec<u8>) -> BoxFutureResult<'a, String> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .push((action.to_string(), serde_json::from_slice(&body)?));
                self.responses
                    .lock()
                    .pop_front()
                    .ok_or_else(|| anyhow!("missing_mock_tsm_response"))
            })
        }
    }

    const COS_CHECK_RESPONSE: &str = r#"{
        "_ReturnCode":"000000",
        "_ReturnMsg":"success",
        "_ReturnData":{
            "seid":"ABCD",
            "isLatest":false,
            "latestCosVersion":"1.2.4",
            "latestBleVersion":"3.0.04",
            "updateType":"mandatory",
            "description":"update",
            "isUpdateSuccess":true
        }
    }"#;

    const BLE_STEP_RESPONSE: &str = r#"{
        "_ReturnCode":"000000",
        "_ReturnMsg":"success",
        "_ReturnData":{"nextStepKey":"03","apduList":["AA"]}
    }"#;

    const END_RESPONSE: &str = r#"{
        "_ReturnCode":"000000",
        "_ReturnMsg":"success",
        "_ReturnData":{"nextStepKey":"end"}
    }"#;

    #[test]
    fn async_cos_check_upgrade_contract_sends_cos_and_ble_versions() {
        let transport =
            MockTransport::new(&["9000", "ABCD9000", "9000", "1239000", "9000", "30039000"]);
        let tsm = MockTsmClient::new(&[COS_CHECK_RESPONSE]);

        let response = futures_lite::future::block_on(cos_check_update(&transport, &tsm)).unwrap();

        assert_eq!(
            response.return_data.latest_ble_version.as_deref(),
            Some("3.0.04")
        );
        let requests = tsm.requests.lock();
        assert_eq!(requests[0].0, constants::TSM_ACTION_COS_CHECK_UPDATE);
        assert_eq!(requests[0].1["cosVersion"], "1.2.3");
        assert_eq!(requests[0].1["bleVersion"], "3.0.03");
        transport.assert_drained();
    }

    #[test]
    fn async_ble_upgrade_contract_reconnects_and_refreshes_version() {
        let transport = MockTransport::new(&[
            "9000",
            "ABCD9000",
            "9000",
            "534E9000",
            "9000",
            "BF2100009000",
            "9000",
            "1239000",
            "9000",
            "30039000",
            "9000",
            "9000",
            "30049000",
        ]);
        let tsm = MockTsmClient::new(&[BLE_STEP_RESPONSE, END_RESPONSE]);

        futures_lite::future::block_on(ble_upgrade(&transport, &tsm)).unwrap();

        assert_eq!(transport.reconnects.load(Ordering::SeqCst), 1);
        let requests = tsm.requests.lock();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].1["stepKey"], "03");
        assert_eq!(requests[1].1["statusWord"], "9000");
        assert_eq!(requests[1].1["bleVersion"], "3.0.04");
        transport.assert_drained();
    }

    #[test]
    fn async_cos_upgrade_contract_chains_ble_update() {
        let transport = MockTransport::new(&[
            "9000",
            "BF2100009000",
            "9000",
            "1239000",
            "9000",
            "ABCD9000",
            "9000",
            "534E9000",
            "9000",
            "ABCD9000",
            "9000",
            "534E9000",
            "9000",
            "BF2100009000",
            "9000",
            "1239000",
            "9000",
            "30039000",
        ]);
        let tsm = MockTsmClient::new(&[END_RESPONSE, END_RESPONSE]);

        futures_lite::future::block_on(cos_upgrade(&transport, &tsm)).unwrap();

        let requests = tsm.requests.lock();
        assert_eq!(requests[0].0, constants::TSM_ACTION_COS_UPGRADE);
        assert_eq!(requests[1].0, constants::TSM_ACTION_BLE_UPDATE);
        transport.assert_drained();
    }
}
