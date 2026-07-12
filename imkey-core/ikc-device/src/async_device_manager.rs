use crate::app_delete::AppDeleteRequest;
use crate::app_download::{AppDownloadRequest, AppDownloadResponse};
use crate::app_update::{AppUpdateRequest, AppUpdateResponse};
use crate::auth_code_storage::{AuthCodeStorageRequest, AuthCodeStorageResponse};
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
use ikc_common::utility::sha256_hash;
pub use ikc_transport::async_transport::{AsyncApduTransport, BoxFutureResult, TransportProfile};
use regex::Regex;
use secp256k1::{ecdh, PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha1::Digest;
use std::convert::TryInto;

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
