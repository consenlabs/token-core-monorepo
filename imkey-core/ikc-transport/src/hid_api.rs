use super::error::HidError;
use crate::message::send_apdu;
use crate::Result;
use anyhow::anyhow;
use hex::FromHex;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use hidapi::{HidApi, HidDevice};
use parking_lot::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
lazy_static! {
    pub static ref HID_API: Result<Mutex<HidApi>> = HidApi::new()
        .map(Mutex::new)
        .map_err(|err| anyhow!("hid_initialization_error: {}", err));
    pub static ref HID_DEVICE: Mutex<Vec<HidDevice>> = Mutex::new(vec![]);
}

//const RETRY_SEC: u64 = 1;
const DEV_VID: u16 = 0x096e;
const DEV_PID: u16 = 0x0891;
const HID_PACKET_SIZE: usize = 65;
const FIRST_PACKET_HEADER_SIZE: usize = 8;
const NEXT_PACKET_HEADER_SIZE: usize = 6;
// A continuation sequence is seven bits in the HID framing protocol.
const MAX_MESSAGE_SIZE: usize = 57 + 128 * 59;
const CHANNEL: [u8; 4] = [0, 0, 0, 1];

fn illegal_response() -> anyhow::Error {
    anyhow!("imkey_transport_illegal_response")
}

fn timeout_millis(timeout: i32) -> Result<i32> {
    timeout
        .checked_mul(1000)
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("imkey_sdk_illegal_argument"))
}

fn validate_handshake_response(packet: &[u8]) -> Result<()> {
    if !(7..=64).contains(&packet.len()) || packet[..4] != CHANNEL || packet[4] != 0x86 {
        return Err(illegal_response());
    }
    let length = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
    if length > 57 || packet.len() < 7 + length {
        return Err(illegal_response());
    }
    Ok(())
}

fn hid_api() -> Result<MutexGuard<'static, HidApi>> {
    HID_API
        .as_ref()
        .map_err(|err| anyhow!("{}", err))
        .map(|hid_api| hid_api.lock())
}

pub fn hid_send(apdu: &str, timeout: i32) -> Result<String> {
    timeout_millis(timeout)?;
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
    if device.write(&first_send_cmd)? != first_send_cmd.len() {
        return Err(illegal_response());
    }
    let mut buf = vec![0; 64];
    let read = device.read_timeout(&mut buf, 300_000)?;
    if read == 0 {
        return Err(HidError::DeviceDataReadTimeOut.into());
    }
    validate_handshake_response(&buf[..read])?;

    let mut receive_first_data_string = String::new();
    for u in &buf[..buf.len()] {
        receive_first_data_string.push_str((format!("{:02X}", u)).as_ref());
    }

    Ok(buf[..read].to_vec())
}

fn read_device_response(device: &hidapi::HidDevice, timeout: i32) -> Result<Vec<u8>> {
    let timeout = timeout_millis(timeout)?;
    let deadline = Instant::now() + Duration::from_millis(timeout as u64);
    decode_device_response(|buf| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HidError::DeviceDataReadTimeOut.into());
        }
        // One deadline covers every frame in the APDU response.
        let millis = remaining.as_millis().max(1).min(timeout as u128) as i32;
        Ok(device.read_timeout(buf, millis)?)
    })
}

fn decode_device_response(mut read: impl FnMut(&mut [u8]) -> Result<usize>) -> Result<Vec<u8>> {
    let mut buf = [0; 64];
    let count = read(&mut buf)?;
    if count == 0 {
        return Err(HidError::DeviceDataReadTimeOut.into());
    }
    if !(7..=64).contains(&count) || buf[..4] != CHANNEL || buf[4] != 0x83 {
        return Err(illegal_response());
    }
    let msg_size = usize::from(u16::from_be_bytes([buf[5], buf[6]]));
    if !(2..=MAX_MESSAGE_SIZE).contains(&msg_size) {
        return Err(illegal_response());
    }
    let mut data = Vec::with_capacity(msg_size);
    let first_size = msg_size.min(57);
    if count < 7 + first_size {
        return Err(illegal_response());
    }
    data.extend_from_slice(&buf[7..7 + first_size]);
    let mut sequence = 0u8;
    while data.len() < msg_size {
        let count = read(&mut buf)?;
        if count == 0 {
            return Err(HidError::DeviceDataReadTimeOut.into());
        }
        let size = (msg_size - data.len()).min(59);
        if !(5 + size..=64).contains(&count) || buf[..4] != CHANNEL || buf[4] != sequence {
            return Err(illegal_response());
        }
        data.extend_from_slice(&buf[5..5 + size]);
        sequence = sequence.checked_add(1).ok_or_else(illegal_response)?;
    }
    Ok(data)
}

fn send_device_message(device: &hidapi::HidDevice, msg: &[u8]) -> Result<usize> {
    let data = encode_device_message(msg)?;
    let mut total_written = 0;
    for chunk in data.chunks(HID_PACKET_SIZE) {
        let written = device.write(chunk)?;
        if written != chunk.len() {
            return Err(illegal_response());
        }
        total_written += written;
    }
    Ok(total_written)
}

fn encode_device_message(msg: &[u8]) -> Result<Vec<u8>> {
    let msg_size = msg.len();
    if msg_size > MAX_MESSAGE_SIZE {
        return Err(anyhow!("imkey_apdu_wrong_length"));
    }
    // first pack
    let headerdata = [
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x83,
        ((msg_size >> 8) & 0xFF) as u8,
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
    Ok(data)
}

pub fn hid_connect(_device_model_name: &str) -> Result<()> {
    //get hid initialization obj
    let hid_api = hid_api()?;

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
    use crate::hid_api::hid_connect;
    use crate::hid_api::{
        decode_device_response, encode_device_message, timeout_millis, validate_handshake_response,
        MAX_MESSAGE_SIZE,
    };
    use crate::message::send_apdu;

    #[test]
    fn hid_handshake_rejects_inconsistent_declared_lengths() {
        for length in [0u16, 2, 57] {
            let mut packet = vec![0, 0, 0, 1, 0x86];
            packet.extend_from_slice(&length.to_be_bytes());
            packet.resize(7 + usize::from(length), 0);
            assert!(validate_handshake_response(&packet).is_ok());
            if length > 0 {
                packet.pop();
                assert!(validate_handshake_response(&packet).is_err());
            }
        }
        for length in [58u16, 256, u16::MAX] {
            let mut packet = vec![0, 0, 0, 1, 0x86];
            packet.extend_from_slice(&length.to_be_bytes());
            assert!(validate_handshake_response(&packet).is_err());
        }
        assert!(validate_handshake_response(&[0, 0, 0, 1, 0x83, 0, 0]).is_err());
    }

    fn decode_packets(packets: Vec<Vec<u8>>) -> crate::Result<Vec<u8>> {
        let mut packets = packets.into_iter();
        decode_device_response(|buf| {
            let packet = packets.next().unwrap_or_default();
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        })
    }

    fn response_packets(message: &[u8]) -> Vec<Vec<u8>> {
        encode_device_message(message)
            .unwrap()
            .chunks(65)
            .map(|packet| packet[1..].to_vec())
            .collect()
    }

    #[test]
    fn hid_roundtrips_lengths_and_big_endian_length() {
        for size in [2, 57, 58, 116, 117, 255, 256, 511, MAX_MESSAGE_SIZE] {
            let message = (0..size).map(|i| i as u8).collect::<Vec<_>>();
            assert_eq!(decode_packets(response_packets(&message)).unwrap(), message);
        }
        assert!(encode_device_message(&vec![0; MAX_MESSAGE_SIZE + 1]).is_err());
    }

    #[test]
    fn hid_rejects_truncated_wrong_channel_command_and_sequence() {
        assert!(decode_packets(vec![]).is_err());
        let packets = response_packets(&vec![0xAB; 300]);
        for length in 0..packets[0].len() {
            let mut truncated = packets.clone();
            truncated[0].truncate(length);
            assert!(decode_packets(truncated).is_err());
        }
        for (packet, offset) in [(0, 3), (0, 4), (1, 3), (1, 4)] {
            let mut corrupted = packets.clone();
            corrupted[packet][offset] ^= 1;
            assert!(decode_packets(corrupted).is_err());
        }
        let mut truncated = packets.clone();
        truncated[1].truncate(5);
        assert!(decode_packets(truncated).is_err());
        let mut oversized = packets;
        oversized[0][5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_packets(oversized).is_err());
    }

    #[test]
    fn hid_malformed_corpus_does_not_panic() {
        let mut state = 0x12345678u32;
        for size in 0..=64 {
            for _ in 0..32 {
                let packet = (0..size)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        state as u8
                    })
                    .collect::<Vec<_>>();
                assert!(std::panic::catch_unwind(|| decode_packets(vec![packet])).is_ok());
            }
        }
        for timeout in [i32::MIN, -1, 0, i32::MAX / 1000 + 1, i32::MAX] {
            assert!(timeout_millis(timeout).is_err());
        }
        assert_eq!(timeout_millis(20).unwrap(), 20_000);
    }

    #[test]
    fn encode_device_message_keeps_short_message_in_one_packet() {
        let encoded = encode_device_message(&[0xAA, 0xBB]).unwrap();
        assert_eq!(encoded, vec![0, 0, 0, 0, 1, 0x83, 0, 2, 0xAA, 0xBB]);
    }

    #[test]
    fn encode_device_message_splits_long_message_after_first_packet() {
        let message = (0..70).collect::<Vec<_>>();
        let encoded = encode_device_message(&message).unwrap();

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
