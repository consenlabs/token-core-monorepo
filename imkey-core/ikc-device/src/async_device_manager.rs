use crate::app_delete::AppDeleteRequest;
use crate::app_download::{AppDownloadRequest, AppDownloadResponse};
use crate::app_update::{AppUpdateRequest, AppUpdateResponse};
use crate::se_activate::SeActivateRequest;
use crate::se_query::{SeQueryRequest, SeQueryResponse};
use crate::se_secure_check::SeSecureCheckRequest;
use crate::{Result, ServiceResponse, TsmStepRequest, TsmStepResponse};
use anyhow::anyhow;
use ikc_common::apdu::{Apdu, ApduCheck, ImkApdu};
use ikc_common::applet;
use ikc_common::constants;
use ikc_common::error::ApduError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::future::Future;
use std::pin::Pin;

pub type BoxFutureResult<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProfile {
    WebUsb,
    WebHid,
    Ble,
    NativeHid,
}

pub trait AsyncApduTransport {
    fn profile(&self) -> TransportProfile;
    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String>;
}

pub trait AsyncTsmClient {
    fn post<'a>(&'a self, action: &'a str, body: Vec<u8>) -> BoxFutureResult<'a, String>;
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
    let response = transport.send_apdu(apdu, 20).await?;
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
