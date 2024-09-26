use wasm_bindgen::JsValue;
use web_sys::{Navigator, Usb, UsbDevice, UsbDeviceRequestOptions, UsbConfiguration, UsbInterface, UsbInTransferResult};
use bytes::{BufMut, BytesMut};
use web_sys::console;
use super::WEB_USB_DEVICE;
use crate::UsbDeviceBox;
use js_sys::{Uint8Array, DataView, Promise, ArrayBuffer}; 
// use crate::Result;
use wasm_bindgen_futures::JsFuture;
use crate::wasm_bindgen::JsCast;

const COMMAND_TYPE_MESSAGE: u8 = 0x43 | 0x80;
const COMMAND_TYPE_CANCEL: u8 = 0x51 | 0x80;
const COMMAND_TYPE_ERROR: u8 = 0x7F | 0x80;
const COMMAND_TYPE_KEEPALIVE: u8 = 0x7B | 0x80;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_PAR: u8 = 0x02;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;

const ERR_DEVICE_BUSY: u8 = 0x06;
const ERR_DEVICE_CANCEL: u8 = 0xFE;
const ERR_OTHER: u8 = 0x07;

pub fn webusb_send(apdu: &str, timeout: i32) -> String {
    "".to_string()
}


fn as_u16_be(value: usize) -> BytesMut {
    let mut b = BytesMut::with_capacity(2);
    b.put_u16(value as u16);
    b
}

fn make_blocks(apdu: &[u8]) -> Vec<BytesMut> {
    let mut data = BytesMut::with_capacity(2 + apdu.len());//指令长度（2） + 指令原值
    data.put(as_u16_be(apdu.len()));
    data.put(apdu);
    println!("data-->{}", hex::encode(data.clone()));
    let packet_size = 64;
    let block_size = packet_size - 5;
    let nb_blocks = (data.len() + block_size - 1) / block_size;
    println!("nb_blocks-->{}", nb_blocks);
    let mut blocks: Vec<BytesMut> = Vec::with_capacity(nb_blocks);
    let mut data_index = 0;

    for i in 0..nb_blocks {
        let mut head = BytesMut::with_capacity(5);

        if i == 0 {
            if apdu.len() == 2 && apdu == b"\x00\x00" {
                head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
                head.put_u8(COMMAND_TYPE_CANCEL);
                head.resize(64, 0);
                blocks.push(head);
                return blocks;
            }
            head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
            head.put_u8(COMMAND_TYPE_MESSAGE);
            let chunk = &data[data_index..std::cmp::min(data.len(), data_index + block_size)];
            data_index += block_size;

            let mut block = BytesMut::with_capacity(64);
            block.put(head);
            block.put(chunk);
            block.resize(64, 0);
            blocks.push(block);
        } else {
            head.put_slice(&[0x00, 0x00, 0x00, 0x00]);
            head.put_u8((i - 1) as u8);
            let chunk = &data[data_index..std::cmp::min(data.len(), data_index + block_size)];
            data_index += block_size;

            let mut block = BytesMut::with_capacity(64);
            block.put(head);
            block.put(chunk);
            block.resize(64, 0);
            blocks.push(block);
        }

        if data_index >= data.len() {
            break;
        }
    }

    blocks
}


#[derive(Default)]
struct ResponseAcc {
    data: Vec<u8>,
    data_length: usize,
    sequence: usize,
}

impl ResponseAcc {
    fn new() -> Self {
        ResponseAcc {
            data: Vec::new(),
            data_length: 0,
            sequence: 0,
        }
    }

    fn reduce_response(&mut self, chunk: &[u8]) {
        // if chunk[4] == COMMAND_TYPE_KEEPALIVE {
        //     return Ok(());
        // }
    
        // if chunk[4] == COMMAND_TYPE_ERROR {
        //     match chunk[7] {
        //         ERR_INVALID_CMD => return Err("Invalid command".into()),
        //         ERR_INVALID_PAR => return Err("Invalid parameter".into()),
        //         ERR_INVALID_LEN => return Err("Invalid length".into()),
        //         ERR_INVALID_SEQ => return Err("Invalid sequence".into()),
        //         ERR_DEVICE_BUSY => return Err("Device busy".into()),
        //         ERR_DEVICE_CANCEL => return Err("Device cancelled".into()),
        //         ERR_OTHER => {
        //             println!("apdu1 <= {}", hex::encode_upper(chunk));
        //             return Ok(());
        //         },
        //         _ => {}
        //     }
        // }
    
        if chunk[4] == COMMAND_TYPE_MESSAGE {
            if self.data_length == 0 {
                self.data_length = ((chunk[5] as usize) << 8) | (chunk[6] as usize);
            }
            self.sequence += 1;
        }
    
        let chunk_data = if self.data.is_empty() { &chunk[7..] } else { &chunk[5..] };
        self.data.extend_from_slice(chunk_data);
        
        if self.data.len() > self.data_length {
            self.data.truncate(self.data_length);
        }
        
    }
    
    fn get_reduced_result(&self) -> Option<Vec<u8>> {
        if self.data.len() == self.data_length {
            Some(self.data.clone())
        } else {
            None
        }
    }
}


pub async fn send_and_receive(device: &UsbDevice, apdu: &[u8]) -> String{
    // let hid_device_obj = WEB_USB_DEVICE.lock();
    // let device = if let Some(device) = &*hid_device_obj {
    //     &device.0
    // } else {
    //     panic!("error");
    // };
    // console::log_1(&format!("Using device: {:?}", device.product_name()).into());

    //send
    let send_list = make_blocks(apdu);
    for val in send_list.iter() {
        console::log_1(&format!("write chunk--> {:?}", hex::encode(val.clone())).into());
        let uint8_array = Uint8Array::new_with_length(val.len() as u32);
        uint8_array.copy_from(val.as_ref());
        device.transfer_out_with_buffer_source(4u8, &uint8_array);
    }

    //revice
    let mut response_acc = ResponseAcc::new();
    let packet_size = 64;
    let mut buffer: Vec<u8> = vec![];
    while true {
        let transfer_promise: Promise = device.transfer_in(5u8, packet_size);

        // 使用 JsFuture::from 将 Promise 转换为 Future，并等待其完成
        let transfer_result: JsValue = JsFuture::from(transfer_promise).await.unwrap(); 
        // // 将结果转换为 USBInTransferResult
        let transfer_result: UsbInTransferResult = transfer_result.dyn_into::<UsbInTransferResult>().unwrap();
        // 获取数据和状态
        let data_view: DataView = transfer_result.data().unwrap().dyn_into::<DataView>().unwrap();
        // 将 DataView 转换为 JsValue 
        let array_buffer: ArrayBuffer = data_view.buffer(); 

        let byte_array: Uint8Array = Uint8Array::new(&array_buffer);
        buffer = byte_array.to_vec();
        if buffer[4] == 0xff {
            continue;
        }
        // response_acc.data_length = u16::from_le_bytes([buffer[5], buffer[6]]) as usize;
        let data_length: [u8; 2] = [buffer[5], buffer[6]];
        response_acc.data_length = u16::from_be_bytes(data_length) as usize;
        response_acc.data = buffer.as_slice()[7..].to_vec();
        let first_chunk_data_length = std::cmp::min(response_acc.data_length, response_acc.data.len());
        response_acc.data = buffer.as_slice()[7..(7 + first_chunk_data_length)].to_vec();
        break;
    }

    // let status = transfer_result.status();
    while true {
        let result = response_acc.get_reduced_result();
        if result.is_some(){
            console::log_1(&format!("read end--> {:?}", hex::encode(&response_acc.data)).into());
            break;
        }
        // response_acc.reduce_response(buffer.as_slice());

        let transfer_promise: Promise = device.transfer_in(5u8, packet_size);
        // 使用 JsFuture::from 将 Promise 转换为 Future，并等待其完成
        let transfer_result: JsValue = JsFuture::from(transfer_promise).await.unwrap(); 
        // // 将结果转换为 USBInTransferResult
        let transfer_result: UsbInTransferResult = transfer_result.dyn_into::<UsbInTransferResult>().unwrap();
        // 获取数据和状态
        let data_view: DataView = transfer_result.data().unwrap().dyn_into::<DataView>().unwrap();
        // 将 DataView 转换为 JsValue 
        let array_buffer: ArrayBuffer = data_view.buffer(); 
        let byte_array: Uint8Array = Uint8Array::new(&array_buffer);
        buffer = byte_array.to_vec();
        let a = buffer[5..].to_vec();
        response_acc.data.extend(buffer[5..].iter());
        if response_acc.data.len() > response_acc.data_length {
            response_acc.data = response_acc.data[..response_acc.data_length].to_vec();
        }
    }

    hex::encode(response_acc.data)
}

#[cfg(test)]
mod test{
    use super::make_blocks;

    #[test]
    fn test(){
        let result = make_blocks(hex::decode("00A40400001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111122").unwrap().as_slice());
        let result = make_blocks(hex::decode("00A40400001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222").unwrap().as_slice());
        // let result = make_blocks(hex::decode("0000").unwrap().as_slice());
        for val in result {
            println!("-->{}", hex::encode(val));
        }
    }

    #[test]
    fn read_test(){
        
    }
}