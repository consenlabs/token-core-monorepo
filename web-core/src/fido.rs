use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

fn navigator_credentials() -> Result<JsValue, JsError> {
    let global: web_sys::Window =
        js_sys::global().dyn_into().map_err(|_| JsError::new("no global Window"))?;
    let nav = global.navigator();
    Ok(Reflect::get(&nav, &"credentials".into())
        .map_err(|_| JsError::new("navigator.credentials not available"))?)
}

// ── FIDO Register ───────────────────────────────────────────────────────────

/// Register a FIDO2 credential via `navigator.credentials.create()`.
///
/// `options`: `{ rp_id, rp_name, user_id (hex), user_name, challenge? (hex) }`
///
/// Returns: `{ credential_id (base64url), attestation_object (base64url), prf_supported }`
#[wasm_bindgen]
pub async fn fido_register(options: JsValue) -> Result<JsValue, JsError> {
    let rp_id = get_string(&options, "rp_id")?;
    let rp_name = get_string(&options, "rp_name")?;
    let user_id_hex = get_string(&options, "user_id")?;
    let user_name = get_string(&options, "user_name")?;

    let user_id_bytes =
        hex::decode(&user_id_hex).map_err(|e| JsError::new(&format!("invalid user_id hex: {e}")))?;

    let challenge_bytes = if let Ok(ch) = get_string(&options, "challenge") {
        hex::decode(&ch).map_err(|e| JsError::new(&format!("invalid challenge hex: {e}")))?
    } else {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        buf.to_vec()
    };

    // Build publicKey options using js_sys::Object
    let rp = Object::new();
    Reflect::set(&rp, &"id".into(), &rp_id.into()).ok();
    Reflect::set(&rp, &"name".into(), &rp_name.into()).ok();

    let user = Object::new();
    Reflect::set(&user, &"id".into(), &Uint8Array::from(user_id_bytes.as_slice()).into()).ok();
    Reflect::set(&user, &"name".into(), &user_name.clone().into()).ok();
    Reflect::set(&user, &"displayName".into(), &user_name.into()).ok();

    let challenge = Uint8Array::from(challenge_bytes.as_slice());

    // pubKeyCredParams
    let param_es256 = Object::new();
    Reflect::set(&param_es256, &"type".into(), &"public-key".into()).ok();
    Reflect::set(&param_es256, &"alg".into(), &JsValue::from(-7)).ok();
    let param_rs256 = Object::new();
    Reflect::set(&param_rs256, &"type".into(), &"public-key".into()).ok();
    Reflect::set(&param_rs256, &"alg".into(), &JsValue::from(-257)).ok();
    let params = Array::new();
    params.push(&param_es256);
    params.push(&param_rs256);

    // authenticatorSelection: discoverable credential, any authenticator type
    let auth_selection = Object::new();
    Reflect::set(&auth_selection, &"residentKey".into(), &"required".into()).ok();
    Reflect::set(&auth_selection, &"requireResidentKey".into(), &JsValue::TRUE).ok();
    Reflect::set(&auth_selection, &"userVerification".into(), &"preferred".into()).ok();

    // extensions with PRF: { prf: {} }
    let extensions = Object::new();
    Reflect::set(&extensions, &"prf".into(), &Object::new().into()).ok();

    let public_key = Object::new();
    Reflect::set(&public_key, &"rp".into(), &rp.into()).ok();
    Reflect::set(&public_key, &"user".into(), &user.into()).ok();
    Reflect::set(&public_key, &"challenge".into(), &challenge.into()).ok();
    Reflect::set(&public_key, &"pubKeyCredParams".into(), &params.into()).ok();
    Reflect::set(&public_key, &"authenticatorSelection".into(), &auth_selection.into()).ok();
    Reflect::set(&public_key, &"extensions".into(), &extensions.into()).ok();

    let create_opts = Object::new();
    Reflect::set(&create_opts, &"publicKey".into(), &public_key.into()).ok();

    // Call navigator.credentials.create(createOpts)
    let creds = navigator_credentials()?;
    let create_fn = Reflect::get(&creds, &"create".into())
        .map_err(|_| JsError::new("WebAuthnNotSupported: credentials.create not available"))?;
    let create_fn: js_sys::Function = create_fn
        .dyn_into()
        .map_err(|_| JsError::new("WebAuthnNotSupported: credentials.create is not a function"))?;
    let promise: Promise = create_fn
        .call1(&creds, &create_opts.into())
        .map_err(|e| js_error_from_jsvalue("credentials.create failed", &e))?
        .dyn_into()
        .map_err(|_| JsError::new("credentials.create did not return a Promise"))?;

    let js_cred = JsFuture::from(promise)
        .await
        .map_err(|e| js_error_from_jsvalue("UserCancelled", &e))?;

    // Extract credential_id from rawId
    let raw_id = Reflect::get(&js_cred, &"rawId".into())
        .map_err(|_| JsError::new("missing rawId on credential"))?;
    let raw_id_bytes = Uint8Array::new(&raw_id).to_vec();
    let credential_id = base64url_encode(&raw_id_bytes);

    // Extract attestationObject from response
    let response = Reflect::get(&js_cred, &"response".into())
        .map_err(|_| JsError::new("missing response on credential"))?;
    let attestation_obj_buf = Reflect::get(&response, &"attestationObject".into())
        .map_err(|_| JsError::new("missing attestationObject"))?;
    let attestation_object = base64url_encode(&Uint8Array::new(&attestation_obj_buf).to_vec());

    // Check PRF support from getClientExtensionResults()
    let get_ext_fn = Reflect::get(&js_cred, &"getClientExtensionResults".into()).ok();
    let prf_supported = get_ext_fn
        .and_then(|f| {
            let f: js_sys::Function = f.dyn_into().ok()?;
            let ext_results = f.call0(&js_cred).ok()?;
            let prf = Reflect::get(&ext_results, &"prf".into()).ok()?;
            let enabled = Reflect::get(&prf, &"enabled".into()).ok()?;
            enabled.as_bool()
        })
        .unwrap_or(false);

    let result = Object::new();
    Reflect::set(&result, &"credential_id".into(), &credential_id.into()).ok();
    Reflect::set(&result, &"attestation_object".into(), &attestation_object.into()).ok();
    Reflect::set(&result, &"prf_supported".into(), &JsValue::from_bool(prf_supported)).ok();
    Ok(result.into())
}

// ── FIDO PRF Key Derivation ─────────────────────────────────────────────────

/// Derive a symmetric key via WebAuthn PRF extension (`navigator.credentials.get()`).
///
/// `options`: `{ credential_id (base64url), rp_id, salt (hex, 32 bytes) }`
///
/// Returns: `{ symmetric_key (hex, 32 bytes) }`
#[wasm_bindgen]
pub async fn fido_derive_prf_key(options: JsValue) -> Result<JsValue, JsError> {
    let credential_id_b64 = get_string(&options, "credential_id")?;
    let rp_id = get_string(&options, "rp_id")?;
    let salt_hex = get_string(&options, "salt")?;

    let cred_id_bytes = base64url_decode(&credential_id_b64)
        .map_err(|e| JsError::new(&format!("invalid credential_id base64url: {e}")))?;
    let salt_bytes =
        hex::decode(&salt_hex).map_err(|e| JsError::new(&format!("invalid salt hex: {e}")))?;
    if salt_bytes.len() != 32 {
        return Err(JsError::new("salt must be 32 bytes (64 hex chars)"));
    }

    let challenge_bytes = {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| JsError::new(&e.to_string()))?;
        buf.to_vec()
    };

    // Build allowCredentials
    let cred_descriptor = Object::new();
    Reflect::set(&cred_descriptor, &"type".into(), &"public-key".into()).ok();
    Reflect::set(
        &cred_descriptor,
        &"id".into(),
        &Uint8Array::from(cred_id_bytes.as_slice()).into(),
    )
    .ok();
    let allow_list = Array::new();
    allow_list.push(&cred_descriptor);

    // Build PRF extension: { prf: { eval: { first: Uint8Array(salt) } } }
    let salt_arr = Uint8Array::from(salt_bytes.as_slice());
    let eval_obj = Object::new();
    Reflect::set(&eval_obj, &"first".into(), &salt_arr.into()).ok();
    let prf_ext = Object::new();
    Reflect::set(&prf_ext, &"eval".into(), &eval_obj.into()).ok();
    let extensions = Object::new();
    Reflect::set(&extensions, &"prf".into(), &prf_ext.into()).ok();

    let public_key = Object::new();
    Reflect::set(&public_key, &"challenge".into(), &Uint8Array::from(challenge_bytes.as_slice()).into()).ok();
    Reflect::set(&public_key, &"rpId".into(), &rp_id.into()).ok();
    Reflect::set(&public_key, &"allowCredentials".into(), &allow_list.into()).ok();
    Reflect::set(&public_key, &"extensions".into(), &extensions.into()).ok();

    let get_opts = Object::new();
    Reflect::set(&get_opts, &"publicKey".into(), &public_key.into()).ok();

    // Call navigator.credentials.get(getOpts)
    let creds = navigator_credentials()?;
    let get_fn = Reflect::get(&creds, &"get".into())
        .map_err(|_| JsError::new("WebAuthnNotSupported: credentials.get not available"))?;
    let get_fn: js_sys::Function = get_fn
        .dyn_into()
        .map_err(|_| JsError::new("WebAuthnNotSupported: credentials.get is not a function"))?;
    let promise: Promise = get_fn
        .call1(&creds, &get_opts.into())
        .map_err(|e| js_error_from_jsvalue("credentials.get failed", &e))?
        .dyn_into()
        .map_err(|_| JsError::new("credentials.get did not return a Promise"))?;

    let js_cred = JsFuture::from(promise)
        .await
        .map_err(|e| js_error_from_jsvalue("UserCancelled", &e))?;

    // Extract PRF result: getClientExtensionResults().prf.results.first
    let get_ext_fn: js_sys::Function = Reflect::get(&js_cred, &"getClientExtensionResults".into())
        .map_err(|_| JsError::new("PrfNotSupported"))?
        .dyn_into()
        .map_err(|_| JsError::new("PrfNotSupported"))?;
    let ext_results = get_ext_fn.call0(&js_cred).map_err(|_| JsError::new("PrfNotSupported"))?;

    let prf = Reflect::get(&ext_results, &"prf".into())
        .map_err(|_| JsError::new("PrfNotSupported: no prf in extension results"))?;
    let results = Reflect::get(&prf, &"results".into())
        .map_err(|_| JsError::new("PrfNotSupported: no prf.results"))?;
    let first = Reflect::get(&results, &"first".into())
        .map_err(|_| JsError::new("PrfNotSupported: no prf.results.first"))?;

    let key_buf = Uint8Array::new(&first).to_vec();
    if key_buf.is_empty() {
        return Err(JsError::new("PrfNotSupported: prf.results.first is empty"));
    }

    let symmetric_key_hex = hex::encode(&key_buf);
    let result = Object::new();
    Reflect::set(&result, &"symmetric_key".into(), &symmetric_key_hex.into()).ok();
    Ok(result.into())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_string(obj: &JsValue, key: &str) -> Result<String, JsError> {
    Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new(&format!("missing or non-string field: {key}")))
}

fn js_error_from_jsvalue(prefix: &str, val: &JsValue) -> JsError {
    if let Some(s) = val.as_string() {
        JsError::new(&format!("{prefix}: {s}"))
    } else {
        JsError::new(prefix)
    }
}

fn base64url_encode(data: &[u8]) -> String {
    use base64_engine::*;
    BASE64URL_NOPAD.encode(data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64_engine::*;
    BASE64URL_NOPAD.decode(s).map_err(|e| e.to_string())
}

mod base64_engine {
    pub use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL_NOPAD;
    pub use base64::Engine as _;
}
