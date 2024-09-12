extern crate wasm_bindgen;
extern crate web_sys;
use wasm_bindgen::prelude::*;
use web_sys::{ Navigator, Window, Usb, UsbDevice};
use web_sys::window;



pub fn test_a() {
    let navigator = window().expect("window should be available").navigator();
    if let Some(usb) = navigator.usb() {
        // 使用 WebUSB API
    } else {
        // console::log_1(&JsValue::from_str("WebUSB not supported"));
    }
}

#[cfg(test)]
mod test{

}