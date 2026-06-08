use super::error::HidError;
use crate::message::send_apdu;
use crate::Result;
use anyhow::anyhow;
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
const HID_PACKET_SIZE: usize = 65;
const FIRST_PACKET_HEADER_SIZE: usize = 8;
const NEXT_PACKET_HEADER_SIZE: usize = 6;

pub fn hid_send(apdu: &str, timeout: i32) -> Result<String> {
    //get hid_device obj
    let hid_device_obj = HID_DEVICE.lock();
    if hid_device_obj.is_empty() {
        return Err(HidError::DeviceConnectInterfaceNotCalled.into());
    }
    let device = hid_device_obj
        .first()
        .ok_or(HidError::DeviceConnectInterfaceNotCalled)?;
    let message = Vec::from_hex(apdu).map_err(|_| anyhow!("imkey_sdk_illegal_argument"))?;
    send_device_message(device, message.as_slice())?;
    let return_data = read_device_response(device, timeout)?;
    let apdu_response = hex::encode_upper(return_data);
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

    let msg_size = buf[5] + buf[6];
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
    let data = encode_device_message(msg);
    let mut total_written = 0;
    for chunk in data.chunks(HID_PACKET_SIZE) {
        total_written += device.write(chunk)?;
    }
    Ok(total_written)
}

fn encode_device_message(msg: &[u8]) -> Vec<u8> {
    let msg_size = msg.len();
    // first pack
    let headerdata = [
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x83,
        (msg_size & 0xFF00) as u8,
        (msg_size & 0x00FF) as u8,
    ];
    let mut data = Vec::new();
    if (msg_size + FIRST_PACKET_HEADER_SIZE) <= HID_PACKET_SIZE {
        data.extend_from_slice(&headerdata[0..FIRST_PACKET_HEADER_SIZE]);
        data.extend_from_slice(&msg[0..msg_size]);
    } else {
        let mut datalenflage = 0;
        let mut flg = 0;
        loop {
            if datalenflage != 0 {
                if datalenflage + HID_PACKET_SIZE - NEXT_PACKET_HEADER_SIZE >= msg_size {
                    data.extend_from_slice(&headerdata[0..5]);
                    data.push(flg as u8);
                    data.extend_from_slice(&msg[datalenflage..msg_size]);
                    break;
                }
                data.extend_from_slice(&headerdata[0..5]);
                data.push(flg as u8);
                flg += 1;
                data.extend_from_slice(
                    &msg[datalenflage..datalenflage + HID_PACKET_SIZE - NEXT_PACKET_HEADER_SIZE],
                );
                datalenflage += HID_PACKET_SIZE - NEXT_PACKET_HEADER_SIZE;
            } else {
                data.extend_from_slice(&headerdata[0..FIRST_PACKET_HEADER_SIZE]);
                data.extend_from_slice(
                    &msg[datalenflage..HID_PACKET_SIZE - FIRST_PACKET_HEADER_SIZE],
                );
                datalenflage += HID_PACKET_SIZE - FIRST_PACKET_HEADER_SIZE;
            }
        }
    }
    data
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
            Ok(())
        }
        Err(err) => {
            // println!("device connect failed : {}", err);
            drop(hid_api);
            //Check if the connection is normal
            match send_apdu("00A40400".to_string()) {
                Ok(_apdu_res) => Ok(()),
                Err(_err) => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hid_api::encode_device_message;
    use crate::hid_api::hid_connect;
    use crate::message::send_apdu;

    #[test]
    fn encode_device_message_keeps_short_message_in_one_packet() {
        let encoded = encode_device_message(&[0xAA, 0xBB]);
        assert_eq!(encoded, vec![0, 0, 0, 0, 1, 0x83, 0, 2, 0xAA, 0xBB]);
    }

    #[test]
    fn encode_device_message_splits_long_message_after_first_packet() {
        let message = (0..70).collect::<Vec<_>>();
        let encoded = encode_device_message(&message);

        assert_eq!(&encoded[..8], &[0, 0, 0, 0, 1, 0x83, 0, 70]);
        assert_eq!(encoded[8..65], message[..57]);
        assert_eq!(&encoded[65..71], &[0, 0, 0, 0, 1, 0]);
        assert_eq!(encoded[71..], message[57..]);
    }

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
