#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use super::hid_api;
use crate::Result;
use anyhow::anyhow;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::thread;
use std::time::Duration;

lazy_static! {
    pub static ref APDU: RwLock<String> = RwLock::new("".to_string());
    pub static ref APDU_RETURN: RwLock<String> = RwLock::new("".to_string());
    pub static ref STRING: Mutex<String> = Mutex::new("".to_string());
    static ref CALLBACK: Mutex<Option<Callback>> = Mutex::new(None);
    pub static ref TEST: RwLock<String> = RwLock::new("".to_string());
}

type Callback = extern "C" fn(*const c_char, i32) -> *const c_char;

pub trait ApduTransport {
    fn send_apdu_timeout(&self, apdu: &str, timeout: i32) -> Result<String>;
}

fn c_string_ptr(value: &str) -> *const c_char {
    let sanitized = value.replace('\0', "");
    match CString::new(sanitized) {
        Ok(value) => value.into_raw(),
        Err(_) => CString::new("")
            .expect("static empty string contains no NUL byte")
            .into_raw(),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub struct HidApduTransport;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl ApduTransport for HidApduTransport {
    fn send_apdu_timeout(&self, apdu: &str, timeout: i32) -> Result<String> {
        hid_api::hid_send(apdu, timeout)
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub struct CallbackApduTransport;

#[cfg(any(target_os = "android", target_os = "ios"))]
impl ApduTransport for CallbackApduTransport {
    fn send_apdu_timeout(&self, apdu: &str, timeout: i32) -> Result<String> {
        send_apdu_with_callback(apdu, timeout)
    }
}

//#[cfg(any(target_os = "macos", target_os = "windows"))]
//lazy_static! {
//   pub static ref DEVICE: Mutex<HidDevice> = Mutex::new(hid_api::hid_connect().unwrap());
//}

#[no_mangle]
pub extern "C" fn default_callback(_apdu: *const c_char, _timeout: i32) -> *const c_char {
    static RESPONSE: &[u8] = b"need set callback!\0";
    RESPONSE.as_ptr() as *const c_char
}

pub fn set_callback(callback: Callback) {
    let mut _callback = CALLBACK.lock();
    *_callback = Some(callback);
}

pub fn get_apdu() -> *const c_char {
    let apdu = APDU.read();
    c_string_ptr(&apdu)
}

#[allow(dead_code)]
fn set_apdu_r(apdu: String) {
    println!("set_apdu_r...");
    loop {
        let mut _apdu = APDU.write();
        if _apdu.is_empty() {
            //debug!("is null set");
            println!("is null set");
            *_apdu = apdu;
            break;
        } else {
            println!("not null...{}", _apdu);
        }
        drop(_apdu);
    }
}

/// # Safety
///
/// `apdu` must be a valid, non-null pointer to a NUL-terminated C string.
pub unsafe fn set_apdu(apdu: *const c_char) {
    if apdu.is_null() {
        return;
    }
    let mut _apdu = APDU.write();
    let c_str: &CStr = unsafe { CStr::from_ptr(apdu) };
    let str_buf: String = c_str.to_string_lossy().into_owned();
    *_apdu = str_buf;
    drop(_apdu);
}

#[allow(dead_code)]
fn get_apdu_return_r() -> Result<String> {
    let timeout = 10; //second
    let loop_max = timeout * 1000 / 100;
    let mut loop_count = 0;
    loop {
        let mut apdu_return = APDU_RETURN.write();
        if !apdu_return.is_empty() {
            println!("get_apdu_return_r not null {}", apdu_return.clone());
            let temp = apdu_return.clone();
            *apdu_return = String::from("");
            return Ok(temp);
        } else {
            println!("get_apdu_return_r is null {}", apdu_return.clone());
        }
        drop(apdu_return);

        loop_count += 1;
        println!("loop time:{}", &loop_count);
        thread::sleep(Duration::from_millis(100));
        if loop_count >= loop_max {
            println!("timeout panic!");
            return Err(anyhow!("imkey_send_apdu_timeout"));
        }
    }
}

pub fn get_apdu_return() -> *const c_char {
    let apdu = APDU_RETURN.read();
    c_string_ptr(&apdu)
}

/// # Safety
///
/// `apdu_return` must be a valid, non-null pointer to a NUL-terminated C string.
pub unsafe fn set_apdu_return(apdu_return: *const c_char) {
    if apdu_return.is_null() {
        return;
    }
    let mut _apdu_return = APDU_RETURN.write();
    let c_str: &CStr = unsafe { CStr::from_ptr(apdu_return) };
    let str_buf: String = c_str.to_string_lossy().into_owned();
    *_apdu_return = str_buf;
    drop(_apdu_return);
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn send_apdu(apdu: String) -> Result<String> {
    send_apdu_timeout(apdu, 20)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn send_apdu_timeout(apdu: String, timeout: i32) -> Result<String> {
    let transport = HidApduTransport;
    transport.send_apdu_timeout(&apdu, timeout)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn send_apdu(apdu: String) -> Result<String> {
    send_apdu_timeout(apdu, 20)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn send_apdu_timeout(apdu: String, timeout: i32) -> Result<String> {
    let transport = CallbackApduTransport;
    transport.send_apdu_timeout(&apdu, timeout)
}

#[cfg(any(target_os = "android", target_os = "ios", test))]
fn send_apdu_with_callback(apdu: &str, timeout: i32) -> Result<String> {
    let callback_guard = CALLBACK.lock();
    let callback = callback_guard
        .as_ref()
        .copied()
        .ok_or_else(|| anyhow!("callback_not_registered"))?;
    invoke_callback(apdu, timeout, callback)
}

#[cfg(any(target_os = "android", target_os = "ios", test))]
fn invoke_callback(apdu: &str, timeout: i32, callback: Callback) -> Result<String> {
    let c_apdu = CString::new(apdu).map_err(|_| anyhow!("imkey_invalid_apdu"))?;
    let response_ptr = callback(c_apdu.as_ptr(), timeout);
    if response_ptr.is_null() {
        return Err(anyhow!("imkey_send_apdu_timeout"));
    }

    // The mobile side owns the response. Copy it while callback response
    // storage is protected by the caller's callback lock.
    let response = unsafe { CStr::from_ptr(response_ptr).to_string_lossy().into_owned() };
    if let Some(error) = response.strip_prefix("communication_error_") {
        Err(anyhow!("{}", error))
    } else {
        Ok(response)
    }
}

#[test]
fn test_rwlock() {
    let r1 = TEST.read();
    println!("test:{}", *r1);

    let r2 = TEST.read();
    println!("test:{}", *r2);
    drop(r1);
    drop(r2);

    let mut w = TEST.write();
    *w = "haha".to_string();
    println!("test:{}", *w);
    drop(w);
}

#[test]
fn test_callback() {
    let apdu = CString::new("00A4040000").unwrap();
    let ptr = default_callback(apdu.as_ptr(), 20);
    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    assert_eq!(result, "need set callback!");
}

#[test]
fn callback_input_is_borrowed_and_response_is_copied() {
    extern "C" fn callback(apdu: *const c_char, timeout: i32) -> *const c_char {
        assert_eq!(timeout, 20);
        let apdu = unsafe { CStr::from_ptr(apdu) }.to_str().unwrap();
        assert_eq!(apdu, "00A4040000");
        static RESPONSE: &[u8] = b"9000\0";
        RESPONSE.as_ptr() as *const c_char
    }

    set_callback(callback);
    for _ in 0..100_000 {
        assert_eq!(send_apdu_with_callback("00A4040000", 20).unwrap(), "9000");
    }
}

#[test]
fn callback_errors_are_explicit() {
    extern "C" fn null_callback(_apdu: *const c_char, _timeout: i32) -> *const c_char {
        std::ptr::null()
    }
    extern "C" fn error_callback(_apdu: *const c_char, _timeout: i32) -> *const c_char {
        static RESPONSE: &[u8] = b"communication_error_disconnected\0";
        RESPONSE.as_ptr() as *const c_char
    }

    assert_eq!(
        invoke_callback("00\0A4", 20, null_callback)
            .unwrap_err()
            .to_string(),
        "imkey_invalid_apdu"
    );
    assert_eq!(
        invoke_callback("00A4", 20, null_callback)
            .unwrap_err()
            .to_string(),
        "imkey_send_apdu_timeout"
    );
    assert_eq!(
        invoke_callback("00A4", 20, error_callback)
            .unwrap_err()
            .to_string(),
        "disconnected"
    );
}

#[test]
fn test_apdu_transport_trait_can_be_mocked() {
    struct EchoTransport;

    impl ApduTransport for EchoTransport {
        fn send_apdu_timeout(&self, apdu: &str, timeout: i32) -> Result<String> {
            Ok(format!("{apdu}:{timeout}"))
        }
    }

    let transport = EchoTransport;
    assert_eq!(
        "00A4040000:20",
        transport.send_apdu_timeout("00A4040000", 20).unwrap()
    );
}
