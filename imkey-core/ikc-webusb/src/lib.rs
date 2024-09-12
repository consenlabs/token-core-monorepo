extern crate wasm_bindgen;
extern crate web_sys;
use wasm_bindgen::prelude::*;
use web_sys::window;
use web_sys::{Navigator, Usb, UsbDevice, Window};

pub fn test_a() {
    let navigator = window().expect("window should be available").navigator();
    let usb = navigator.usb();
}

#[cfg(test)]
mod test {}
