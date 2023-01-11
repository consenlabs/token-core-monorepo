use super::error::HidError;
use crate::message::send_apdu;
use crate::Result;
use hex::FromHex;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use hidapi::{HidApi, HidDevice};
use parking_lot::Mutex;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
lazy_static! {
    pub static ref HID_API: Mutex<HidApi> =
        Mutex::new(HidApi::new().expect("hid_initialization_error"));
    pub static ref HID_DEVICE: Mutex<Vec<HidDevice>> = Mutex::new(vec![]);
}

//const RETRY_SEC: u64 = 1;
const DEV_VID: u16 = 0x096e;
const DEV_PID: u16 = 0x0891;

pub fn hid_send(apdu: &String, timeout: i32) -> Result<String> {
    //get hid_device obj
    let hid_device_obj: &Vec<HidDevice> = &HID_DEVICE.lock();
    if hid_device_obj.is_empty() {
        drop(hid_device_obj);
        return Err(HidError::DeviceConnectInterfaceNotCalled.into());
    }
    // println!("-->{}", apdu);
    send_device_message(
        &hid_device_obj.get(0).unwrap(),
        Vec::from_hex(apdu.as_str()).unwrap().as_slice(),
    )?;
    let return_data = read_device_response(&hid_device_obj.get(0).unwrap(), timeout)?;
    //    drop(hid_device_obj);
    let apdu_response = hex::encode_upper(return_data);
    // println!("<--{}", apdu_response.clone());
    Ok(apdu_response)
}

fn first_write_read_device_response(device: &hidapi::HidDevice) -> Result<Vec<u8>> {
    let first_send_cmd: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 0x00];
    let mut send_first_data_string = String::new();
    for u in &first_send_cmd[..first_send_cmd.len()] {
        send_first_data_string.push_str((format!("{:02X}", u)).as_ref());
    }
    let _res = device.write(&first_send_cmd)?;
    let mut buf = vec![0; 64];
    device.read_timeout(&mut buf, 300_000)?;

    let mut receive_first_data_string = String::new();
    for u in &buf[..buf.len()] {
        receive_first_data_string.push_str((format!("{:02X}", u)).as_ref());
    }

    Ok(buf[..64].to_vec())
}

fn read_device_response(device: &hidapi::HidDevice, timeout: i32) -> Result<Vec<u8>> {
    let mut buf = vec![0; 64];
    device.read(&mut buf)?;

    let msg_size = (buf[5] as u8 & 0xFF) + (buf[6] as u8 & 0xFF);
    let mut data = Vec::new();
    data.extend_from_slice(&buf[7..]);
    while data.len() < (msg_size as usize) {
        device.read_timeout(&mut buf, timeout * 1000)?;
        data.extend_from_slice(&buf[5..64]);
    }
    data.truncate(msg_size as usize);

    let mut receive_data_string = String::new();
    for u in &data[..data.len()] {
        receive_data_string.push_str((format!("{:02X}", u)).as_ref());
    }

    Ok(data[..msg_size as usize].to_vec())
}

fn send_device_message(device: &hidapi::HidDevice, msg: &[u8]) -> Result<usize> {
    let msg_size = msg.len();
    let mut headerdata = Vec::new();
    // first pack
    headerdata.push(0x00 as u8);
    headerdata.push(0x00 as u8);
    headerdata.push(0x00 as u8);
    headerdata.push(0x00 as u8);
    headerdata.push(0x01 as u8);
    headerdata.push(0x83 as u8);
    headerdata.push((msg_size & 0xFF00) as u8);
    headerdata.push((msg_size & 0x00FF) as u8);
    let mut data = Vec::new();
    if (msg_size + 8) <= 65 {
        data.extend_from_slice(&headerdata[0..8]);
        data.extend_from_slice(&msg[0..msg_size]);
    } else {
        let mut datalenflage = 0;
        let mut flg = 0;
        loop {
            if !(datalenflage == 0) {
                if datalenflage + 65 - 6 >= msg_size {
                    data.extend_from_slice(&headerdata[0..5]);
                    data.push(flg as u8);
                    data.extend_from_slice(&msg[datalenflage..msg_size]);
                    break;
                }
                data.extend_from_slice(&headerdata[0..5]);
                data.push(flg as u8);
                flg = 1 + flg;
                data.extend_from_slice(&msg[datalenflage..datalenflage + 65 - 6]);
                datalenflage += 65 - 6;
            } else {
                data.extend_from_slice(&headerdata[0..8]);
                data.extend_from_slice(&msg[datalenflage..65 - 8]);
                datalenflage += 65 - 8;
            }
        }
    }

    let total_written = 0;
    for chunk in data.chunks(65) {
        device.write(&chunk)?;
    }
    Ok(total_written)
}

pub fn hid_connect(_device_model_name: &str) -> Result<()> {
    //get hid initialization obj
    let hid_api = HID_API.lock();

    //connect device
    match hid_api.open(DEV_VID, DEV_PID) {
        Ok(hid_device) => {
            // println!("device connected!!!");
            first_write_read_device_response(&hid_device)?;
            drop(hid_api);
            let mut hid_device_obj = HID_DEVICE.lock();
            *hid_device_obj = vec![hid_device];
            drop(hid_device_obj);
            send_apdu("00A40400".to_string())?;
            return Ok(());
        }
        Err(err) => {
            // println!("device connect failed : {}", err);
            drop(hid_api);
            //Check if the connection is normal
            match send_apdu("00A40400".to_string()) {
                Ok(_apdu_res) => {
                    return Ok(());
                }
                Err(_err) => {
                    return Err(err.into());
                }
            }
        }
    };
}

#[cfg(test)]
mod test {
    use crate::hid_api::hid_connect;
    use crate::message::send_apdu;

    #[test]
    fn hid_test() {
        let connect_result = hid_connect("imKey Pro");
        match connect_result {
            Ok(()) => {
                assert!(send_apdu("00A4040000".to_string()).is_ok());
                assert!(send_apdu("00A404007500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100".to_string()).is_ok())
            }
            Err(err) => println!("{}", err),
        }
    }

    #[test]
    fn hid_connect_test() {
        //device is empty test
        assert!(send_apdu("00A4040000".to_string()).is_err());

        //Test equipment has been connected and connected again
        let connect_result = hid_connect("imKey Pro");
        if connect_result.is_ok() {
            assert!(hid_connect("imKey Pro").is_ok());
        }
    }

    #[test]
    #[ignore]
    fn hid_device_is_empty_test() {
        assert!(send_apdu("00A4040000".to_string()).is_err()); //same test in hid_connect_test
    }
}
