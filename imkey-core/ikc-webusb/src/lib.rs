extern crate wasm_bindgen;
extern crate web_sys;
use wasm_bindgen::prelude::*;
use web_sys::window;
use web_sys::{Navigator, Usb, UsbDevice, UsbDeviceRequestOptions};
use js_sys::Promise;
use wasm_bindgen_futures::JsFuture;
use serde_json::Value;
use web_sys::console;
use serde_wasm_bindgen::to_value;
use parking_lot::Mutex;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    // 使用 Arc<Mutex<...>> 来包装 UsbDevice
    pub static ref WEB_USB_DEVICE: Mutex<Option<UsbDeviceBox>> = Mutex::new(None);
}
#[derive(Debug)]
pub struct UsbDeviceBox(UsbDevice);
unsafe impl Send for UsbDeviceBox {}

// #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
// lazy_static! {
//     pub static ref WEB_USB_DEVICE: Mutex<Vec<UsbDevice>> = Mutex::new(vec![]);
// }

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn connect() {
    // alert(&format!("Hello, world!"));
    web_sys::console::log_1(&"enter connect function".into());
    let navigator = window().expect("window should be available").navigator();
    web_sys::console::log_1(&"获取navigator".into());
    let usb: Usb = navigator.usb();
    web_sys::console::log_1(&"访问usb".into());

    // 手动构造过滤器对象
    let filters = vec![serde_json::json!({
        "vendorId": 0x096e, // 替换为你的设备供应商 ID
        "productId": 0x0891  // 替换为你的设备产品 ID
    })];
    web_sys::console::log_1(&"定义过滤器".into());
    // 创建 UsbDeviceRequestOptions
    let options = UsbDeviceRequestOptions::new(&to_value(&vec![filters]).unwrap());
    web_sys::console::log_1(&"创建 UsbDeviceRequestOptions".into());
    // 请求设备
    // let options = JsValue::from_serde(&filters).unwrap();
    let promise = usb.request_device(&options);
    web_sys::console::log_1(&"请求设备".into());
    // 处理请求设备的结果
    let device = wasm_bindgen_futures::JsFuture::from(promise).await;
    // 请求设备
    match device {
        Ok(device) => {
            console::log_1(&"Device requested successfully".into());
            // 继续处理设备
            let device: UsbDevice = device.unchecked_into();
            web_sys::console::log_1(&format!("++++++++++++Product Name: {:?}", device.product_name()).into());
            web_sys::console::log_1(&format!("++++++++++++Manufacturer Name: {:?}", device.manufacturer_name()).into());
            web_sys::console::log_1(&format!("++++++++++++Serial Number: {:?}", device.serial_number()).into());
            web_sys::console::log_1(&format!("++++++++++++Product ID: {:?}", device.product_id()).into());
            web_sys::console::log_1(&format!("++++++++++++Vendor ID: {:?}", device.vendor_id()).into());
            let mut hid_device_obj = WEB_USB_DEVICE.lock();
            *hid_device_obj = Some(UsbDeviceBox(device));
        },
        Err(err) => {
            console::log_1(&format!("Error requesting device: {:?}", err).into());
        }
    }



}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn send_apdu(apdu: &str) -> Result<String, JsValue> {
    console::log_1(&"enter send_apdu function".into());
    // 访问存储的 UsbDevice
    let hid_device_obj = WEB_USB_DEVICE.lock();
    if let Some(device) = &*hid_device_obj {
        // 这里可以使用 device 进行操作
        console::log_1(&format!("Using device: {:?}", device.0.product_name()).into());
    } else {
        console::log_1(&"No device found".into());
    }
    Ok("return data!!!".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn connect() {
    println!("WebUSB functionality is not available in non-WASM environments");
}

#[cfg(test)]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg(test)]
mod test {
    
    use super::*;
    use wasm_bindgen_test::*;
    
    #[wasm_bindgen_test]  
    async fn test_connect() {
        println!("开始测试 connect 函数");
        super::connect().await;
        println!("完成测试");
    }
}
