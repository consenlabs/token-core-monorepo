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
    // pub static ref CALLBACK: Mutex<extern "C" fn(*const u8) -> *const u8> = Mutex::new(default_callback);
    pub static ref CALLBACK: Mutex<extern "C" fn(*const c_char, i32) -> *const c_char> = Mutex::new(default_callback);

    pub static ref TEST:RwLock<String> = RwLock::new("".to_string());
}

//#[cfg(any(target_os = "macos", target_os = "windows"))]
//lazy_static! {
//   pub static ref DEVICE: Mutex<HidDevice> = Mutex::new(hid_api::hid_connect().unwrap());
//}

#[no_mangle]
pub extern "C" fn default_callback(_apdu: *const c_char, _timeout: i32) -> *const c_char {
    std::ptr::null()
}

pub fn set_callback(callback: extern "C" fn(apdu: *const c_char, timeout: i32) -> *const c_char) {
    let mut _callback = CALLBACK.lock();
    *_callback = callback;
}

pub fn get_apdu() -> *const c_char {
    let apdu = APDU.read();
    CString::new(apdu.to_owned()).unwrap().into_raw()
}

#[allow(dead_code)]
fn set_apdu_r(apdu: String) {
    println!("set_apdu_r...");
    loop {
        let mut _apdu = APDU.write();
        if *_apdu == "" {
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

/// `apdu` is borrowed for the duration of this call and may be null.
pub unsafe fn set_apdu(apdu: *const c_char) {
    let value = if apdu.is_null() {
        None
    } else {
        CStr::from_ptr(apdu).to_str().ok()
    };
    *APDU.write() = value.unwrap_or("").to_owned();
}

#[allow(dead_code)]
fn get_apdu_return_r() -> Result<String> {
    let timeout = 10; //second
    let loop_max = timeout * 1000 / 100;
    let mut loop_count = 0;
    loop {
        let mut apdu_return = APDU_RETURN.write();
        if *apdu_return != "" {
            println!("get_apdu_return_r not null {}", apdu_return.clone());
            let temp = apdu_return.clone();
            *apdu_return = String::from("");
            return Ok(String::from(temp));
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
    CString::new(apdu.to_owned()).unwrap().into_raw()
}

/// `apdu_return` is borrowed; malformed strings become a transport error.
pub unsafe fn set_apdu_return(apdu_return: *const c_char) {
    let value = if apdu_return.is_null() {
        None
    } else {
        CStr::from_ptr(apdu_return).to_str().ok()
    };
    *APDU_RETURN.write() = value
        .unwrap_or("communication_error_imkey_transport_illegal_response")
        .to_owned();
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn send_apdu(apdu: String) -> Result<String> {
    send_apdu_timeout(apdu, 20)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn send_apdu_timeout(apdu: String, timeout: i32) -> Result<String> {
    hid_api::hid_send(&apdu, timeout)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn send_apdu(apdu: String) -> Result<String> {
    send_apdu_timeout(apdu, 20)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn send_apdu_timeout(apdu: String, timeout: i32) -> Result<String> {
    send_apdu_with_callback(&apdu, timeout)
}

#[cfg(any(target_os = "android", target_os = "ios", test))]
fn send_apdu_with_callback(apdu: &str, timeout: i32) -> Result<String> {
    if timeout <= 0 {
        return Err(anyhow!("imkey_sdk_illegal_argument"));
    }
    let request = CString::new(apdu).map_err(|_| anyhow!("imkey_sdk_illegal_argument"))?;
    // Serialize the callback and the borrowed response copy as one operation.
    let callback = CALLBACK.lock();
    // The request lives through the call; the callback retains ownership of its response.
    let ptr = callback(request.as_ptr(), timeout);
    if ptr.is_null() {
        return Err(anyhow!("imkey_transport_illegal_response"));
    }
    let response = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| anyhow!("imkey_transport_illegal_response"))?;
    if let Some(error) = response.strip_prefix("communication_error_") {
        return Err(anyhow!("{}", error));
    }
    if response.len() < 4
        || response.len() % 2 != 0
        || !response.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!("imkey_transport_illegal_response"));
    }
    Ok(response.to_owned())
}

#[cfg(test)]
mod ffi_security_tests {
    use super::*;
    static LOCK: Mutex<()> = Mutex::new(());
    extern "C" fn valid(_: *const c_char, _: i32) -> *const c_char {
        b"9000\0".as_ptr() as *const c_char
    }
    extern "C" fn invalid(_: *const c_char, _: i32) -> *const c_char {
        b"\xff\0".as_ptr() as *const c_char
    }
    #[test]
    fn callback_and_setter_malformed_inputs_do_not_panic() {
        let _lock = LOCK.lock();
        let previous = *CALLBACK.lock();
        set_callback(valid);
        assert_eq!(send_apdu_with_callback("00A4040000", 20).unwrap(), "9000");
        assert!(send_apdu_with_callback("00A4\0", 20).is_err());
        assert!(send_apdu_with_callback("00A4", 0).is_err());
        set_callback(default_callback);
        assert!(send_apdu_with_callback("00A4", 20).is_err());
        set_callback(invalid);
        assert!(send_apdu_with_callback("00A4", 20).is_err());
        unsafe {
            set_apdu(std::ptr::null());
            set_apdu_return(std::ptr::null());
            set_apdu(b"\xff\0".as_ptr() as *const c_char);
            set_apdu_return(b"\xff\0".as_ptr() as *const c_char);
        }
        assert!(APDU.read().is_empty());
        assert!(APDU_RETURN.read().starts_with("communication_error_"));
        set_callback(previous);
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
    let callback = CALLBACK.lock();
    let ptr = callback(
        CString::new("00A4040000".to_owned()).unwrap().into_raw(),
        20,
    );
    if ptr.is_null() {
        return;
    }
    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    println!("callback result:{:#?}", result);
}
