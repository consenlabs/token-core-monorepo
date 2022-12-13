#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use super::hid_api;
use crate::Result;
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
    CString::new("need set callback!".to_owned())
        .unwrap()
        .into_raw()
}

pub fn set_callback(callback: extern "C" fn(apdu: *const c_char, timeout: i32) -> *const c_char) {
    let mut _callback = CALLBACK.lock();
    *_callback = callback;
}

pub fn get_apdu() -> *const c_char {
    let apdu = APDU.read();
    return CString::new(apdu.to_owned()).unwrap().into_raw();
}

#[allow(dead_code)]
fn set_apdu_r(apdu: String) {
    println!("set_apdu_r...");
    loop {
        let mut _apdu = APDU.write();
        if *_apdu == "" {
            //debug!("is null set");
            println!("is null set");
            *_apdu = String::from(apdu.clone());
            break;
        } else {
            println!("not null...{}", _apdu);
        }
        drop(_apdu);
    }
}

pub fn set_apdu(apdu: *const c_char) {
    let mut _apdu = APDU.write();
    let c_str: &CStr = unsafe { CStr::from_ptr(apdu) };
    let str_slice: &str = c_str.to_str().unwrap();
    let str_buf: String = str_slice.to_owned();
    //debug!("set_apdu...{}", str_buf);
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
        if *apdu_return != "" {
            println!("get_apdu_return_r not null {}", apdu_return.clone());
            let temp = apdu_return.clone();
            *apdu_return = String::from("");
            return Ok(String::from(temp.to_owned()));
        } else {
            println!("get_apdu_return_r is null {}", apdu_return.clone());
        }
        drop(apdu_return);

        loop_count = loop_count + 1;
        println!("loop time:{}", &loop_count);
        thread::sleep(Duration::from_millis(100));
        if loop_count >= loop_max {
            println!("timeout panic!");
            return Err(format_err!("imkey_send_apdu_timeout"));
        }
    }
}

pub fn get_apdu_return() -> *const c_char {
    let apdu = APDU_RETURN.read();
    //debug!("get_apdu_return...{}", apdu.clone());
    return CString::new(apdu.to_owned()).unwrap().into_raw();
}

pub fn set_apdu_return(apdu_return: *const c_char) {
    let mut _apdu_return = APDU_RETURN.write();
    let c_str: &CStr = unsafe { CStr::from_ptr(apdu_return) };
    let str_slice: &str = c_str.to_str().unwrap();
    let str_buf: String = str_slice.to_owned();
    //debug!("set_apdu_return...{}", str_buf);
    *_apdu_return = str_buf;
    drop(_apdu_return);
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
    // set_apdu_r(apdu);
    // get_apdu_return_r().unwrap()

    let callback = CALLBACK.lock();
    let ptr = callback(CString::new(apdu).unwrap().into_raw(), timeout);

    // let mut res = unsafe { Ok(CStr::from_ptr(ptr).to_string_lossy().into_owned()) }?;
    // let prefix = "communication_error_";
    // if res.starts_with(prefix){
    //     let error = &res[..prefix.len()-1];
    //     return Err(format_err!("{}", error))
    // }else {
    //     return Ok(res)
    // }

    unsafe {
        let res = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        let prefix = "communication_error_";
        return if res.starts_with(prefix) {
            let error = &res[prefix.len()..];
            println!("{}", error);
            Err(format_err!("{}", error))
        } else {
            println!("{}", res);
            Ok(res)
        };
    }
}

#[test]
fn test_rwlock() {
    let r1 = TEST.read().unwrap();
    println!("test:{}", *r1);

    let r2 = TEST.read().unwrap();
    println!("test:{}", *r2);
    drop(r1);
    drop(r2);

    let mut w = TEST.write().unwrap();
    *w = "haha".to_string();
    println!("test:{}", *w);
    drop(w);
}

#[test]
fn test_callback() {
    let callback = CALLBACK.lock().unwrap();
    let ptr = callback(
        CString::new("00A4040000".to_owned()).unwrap().into_raw(),
        20,
    );
    let result = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    println!("callback result:{:#?}", result);
}
