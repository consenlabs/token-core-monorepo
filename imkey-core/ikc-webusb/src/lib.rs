extern crate wasm_bindgen;
extern crate web_sys;
use wasm_bindgen::prelude::*;
use web_sys::window;
use web_sys::{Navigator, Usb, UsbDevice, Window};
use js_sys::Promise;
use wasm_bindgen_futures::JsFuture;
use serde_json::Value;
// #[cfg(test)]
// use wasm_bindgen_test::*;
use web_sys::console;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn connect() {
    web_sys::console::log_1(&"enter connect function".into());
    let navigator = window().expect("window should be available").navigator();
    let usb: Usb = navigator.usb();
    // 定义连接时的设备选项（例如供应商 ID 或产品 ID）
    // let options = JsValue::from_serde(&{
    //     let mut obj = serde_json::Map::new();
    //     obj.insert("filters".to_string(), vec![{
    //         let mut filter = serde_json::Map::new();
    //         filter.insert("vendorId".to_string(), 0x096e.into()); // 替换为你的设备供应商 ID
    //         filter
    //     }].into());
    //     obj
    // }).unwrap();

    println!("aaaaaaaa");

    // 请求连接 USB 设备
    let promise: Promise = usb.get_devices();
    let future = JsFuture::from(promise);
    let result = wasm_bindgen_futures::spawn_local(async move {
        match future.await {
            Ok(devices) => {
                // 处理成功获取的设备列表
                let devices: js_sys::Array = devices.unchecked_into();
                println!("Found {} devices", devices.length());
                for i in 0..devices.length() {
                    let device = devices.get(i);
                    if !device.is_undefined() {
                        let device: UsbDevice = device.unchecked_into();
                        println!("Device {}:", i);
                        println!("  Product Name: {:?}", device.product_name());
                        println!("  Manufacturer Name: {:?}", device.manufacturer_name());
                        println!("  Serial Number: {:?}", device.serial_number());
                        println!("  Product ID: {:?}", device.product_id());
                        println!("  Vendor ID: {:?}", device.vendor_id());
                    }
                }
                // 现在你可以使用 devices
                
                
            },
            Err(e) => {
                // 处理错误
                println!("Error getting devices: {:?}", e);
            }
        }
    });
    // // 使用 JsFuture 来等待 Promise
    // let result = JsFuture::from(promise).unwrap();
            
    // // 将结果转换为 Vec<UsbDevice>
    // let devices: Vec<UsbDevice> = result.into_serde().unwrap();

    // // 现在你可以使用 devices
    // println!("Found {} devices", devices.len());



}

#[cfg(not(target_arch = "wasm32"))]
pub fn connect() {
    let message = "Test is running4";
    web_sys::console::log_1(&message.into());
    println!("WebUSB functionality is not available in non-WASM environments");
}

#[cfg(test)]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg(test)]
mod test {
    
    use super::*;
    use wasm_bindgen_test::*;
    
    #[wasm_bindgen_test]  
    fn test_connect() {
        println!("开始测试 connect 函数");
        super::connect();
        println!("完成测试");
    }
}
