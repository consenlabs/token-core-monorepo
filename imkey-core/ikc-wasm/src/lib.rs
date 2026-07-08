use std::cell::RefCell;

use ikc_device::async_device_manager::{
    self, AsyncApduTransport, AsyncTsmClient, BoxFutureResult, TransportProfile,
};
use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

thread_local! {
    static TRANSPORT: RefCell<Option<JsValue>> = const { RefCell::new(None) };
    static TSM_CLIENT: RefCell<Option<JsValue>> = const { RefCell::new(None) };
    static TRANSPORT_PROFILE: RefCell<TransportProfile> = const { RefCell::new(TransportProfile::WebUsb) };
}

fn js_err(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn js_value_message(value: &JsValue, fallback: &str) -> String {
    if let Some(message) = value.as_string() {
        return message;
    }
    Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn map_err(error: anyhow::Error) -> JsValue {
    js_err(error.to_string())
}

fn normalize_hex(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn transport() -> Result<JsValue, JsValue> {
    TRANSPORT.with(|transport| {
        transport
            .borrow()
            .clone()
            .ok_or_else(|| js_err("imkey_transport_not_set"))
    })
}

fn tsm_client() -> Result<JsValue, JsValue> {
    TSM_CLIENT.with(|client| {
        client
            .borrow()
            .clone()
            .ok_or_else(|| js_err("imkey_tsm_client_not_set"))
    })
}

fn transport_profile() -> TransportProfile {
    TRANSPORT_PROFILE.with(|profile| *profile.borrow())
}

fn parse_transport_profile(value: &str) -> Result<TransportProfile, JsValue> {
    match value.trim().to_ascii_lowercase().as_str() {
        "webusb" | "web_usb" => Ok(TransportProfile::WebUsb),
        "webhid" | "web_hid" => Ok(TransportProfile::WebHid),
        "ble" | "bluetooth" => Ok(TransportProfile::Ble),
        "hid" | "native_hid" => Ok(TransportProfile::NativeHid),
        _ => Err(js_err("imkey_unknown_transport_profile")),
    }
}

async fn call_transport(apdu: &str, timeout_ms: Option<u32>) -> Result<String, JsValue> {
    let transport = transport()?;
    let method = Reflect::get(&transport, &JsValue::from_str("sendApduRaw"))?;
    let method = method
        .dyn_ref::<Function>()
        .ok_or_else(|| js_err("transport.sendApduRaw is not a function"))?;

    let promise = match timeout_ms {
        Some(timeout_ms) => method.call2(
            &transport,
            &JsValue::from_str(apdu),
            &JsValue::from_f64(timeout_ms as f64),
        )?,
        None => method.call1(&transport, &JsValue::from_str(apdu))?,
    };
    let promise = promise
        .dyn_into::<Promise>()
        .map_err(|_| js_err("transport.sendApduRaw must return a Promise"))?;
    let response = JsFuture::from(promise).await?;
    response
        .as_string()
        .map(|value| normalize_hex(&value))
        .ok_or_else(|| js_err("transport response must be a hex string"))
}

async fn call_tsm(action: &str, body_json: &str) -> Result<String, JsValue> {
    let client = tsm_client()?;
    let method = Reflect::get(&client, &JsValue::from_str("post"))?;
    let method = method
        .dyn_ref::<Function>()
        .ok_or_else(|| js_err("tsmClient.post is not a function"))?;

    let promise = method.call2(
        &client,
        &JsValue::from_str(action),
        &JsValue::from_str(body_json),
    )?;
    let promise = promise
        .dyn_into::<Promise>()
        .map_err(|_| js_err("tsmClient.post must return a Promise"))?;
    let response = JsFuture::from(promise).await?;
    response
        .as_string()
        .ok_or_else(|| js_err("tsm client response must be a string"))
}

struct JsApduTransport {
    profile: TransportProfile,
}

impl AsyncApduTransport for JsApduTransport {
    fn profile(&self) -> TransportProfile {
        self.profile
    }

    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String> {
        Box::pin(async move {
            let timeout_ms = timeout.max(1) as u32 * 1000;
            call_transport(apdu, Some(timeout_ms))
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_send_apdu_error")))
        })
    }
}

struct JsTsmClient;

impl AsyncTsmClient for JsTsmClient {
    fn post<'a>(&'a self, action: &'a str, body: Vec<u8>) -> BoxFutureResult<'a, String> {
        Box::pin(async move {
            let body_json = String::from_utf8(body)?;
            call_tsm(action, &body_json)
                .await
                .map_err(|err| anyhow::anyhow!(js_value_message(&err, "imkey_tsm_request_error")))
        })
    }
}

fn js_transport() -> JsApduTransport {
    JsApduTransport {
        profile: transport_profile(),
    }
}

#[wasm_bindgen]
pub fn set_transport(transport: JsValue) {
    TRANSPORT.with(|slot| {
        *slot.borrow_mut() = Some(transport);
    });
}

#[wasm_bindgen]
pub fn set_transport_profile(profile: &str) -> Result<(), JsValue> {
    let profile = parse_transport_profile(profile)?;
    TRANSPORT_PROFILE.with(|slot| {
        *slot.borrow_mut() = profile;
    });
    Ok(())
}

#[wasm_bindgen]
pub fn set_tsm_client(client: JsValue) {
    TSM_CLIENT.with(|slot| {
        *slot.borrow_mut() = Some(client);
    });
}

#[wasm_bindgen]
pub fn clear_transport() {
    TRANSPORT.with(|slot| {
        *slot.borrow_mut() = None;
    });
    TRANSPORT_PROFILE.with(|slot| {
        *slot.borrow_mut() = TransportProfile::WebUsb;
    });
}

#[wasm_bindgen]
pub fn clear_tsm_client() {
    TSM_CLIENT.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[wasm_bindgen]
pub async fn send_apdu(apdu_hex: &str, timeout_ms: Option<u32>) -> Result<String, JsValue> {
    let response = call_transport(&normalize_hex(apdu_hex), timeout_ms).await?;
    ikc_common::apdu::ApduCheck::check_response(&response).map_err(map_err)?;
    Ok(response)
}

#[wasm_bindgen]
pub async fn send_apdu_unchecked(
    apdu_hex: &str,
    timeout_ms: Option<u32>,
) -> Result<String, JsValue> {
    call_transport(&normalize_hex(apdu_hex), timeout_ms).await
}

#[wasm_bindgen]
pub async fn tsm_post(action: &str, body_json: &str) -> Result<String, JsValue> {
    call_tsm(action, body_json).await
}

#[wasm_bindgen]
pub async fn get_seid() -> Result<String, JsValue> {
    async_device_manager::get_se_id(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_sn() -> Result<String, JsValue> {
    async_device_manager::get_sn(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_firmware_version() -> Result<String, JsValue> {
    async_device_manager::get_firmware_version(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_battery_power() -> Result<String, JsValue> {
    async_device_manager::get_battery_power(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_life_time() -> Result<String, JsValue> {
    async_device_manager::get_life_time(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn get_cert() -> Result<String, JsValue> {
    async_device_manager::get_cert(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn bind_display_code() -> Result<(), JsValue> {
    async_device_manager::bind_display_code(&js_transport())
        .await
        .map_err(map_err)
}

#[wasm_bindgen]
pub async fn secure_check() -> Result<String, JsValue> {
    async_device_manager::secure_check(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn activate_device() -> Result<String, JsValue> {
    async_device_manager::activate(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn check_update() -> Result<String, JsValue> {
    let response = async_device_manager::check_update(&js_transport(), &JsTsmClient)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_check_update_error"))
}

#[wasm_bindgen]
pub async fn app_download(app_name: &str) -> Result<String, JsValue> {
    let response = async_device_manager::app_download(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_app_download_error"))
}

#[wasm_bindgen]
pub async fn app_update(app_name: &str) -> Result<String, JsValue> {
    let response = async_device_manager::app_update(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    serde_json::to_string(&response).map_err(|_| js_err("serialize_app_update_error"))
}

#[wasm_bindgen]
pub async fn app_delete(app_name: &str) -> Result<String, JsValue> {
    async_device_manager::app_delete(&js_transport(), &JsTsmClient, app_name)
        .await
        .map_err(map_err)?;
    Ok(r#"{"result":"success"}"#.to_string())
}

#[wasm_bindgen]
pub async fn get_device_info() -> Result<String, JsValue> {
    let info = async_device_manager::get_device_info(&js_transport())
        .await
        .map_err(map_err)?;
    serde_json::to_string(&info).map_err(|_| js_err("serialize_device_info_error"))
}
