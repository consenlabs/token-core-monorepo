use crate::constants::{BTC_AID, COSMOS_AID, EOS_AID, ETH_AID, LC_MAX};
use crate::error::ApduError;
use crate::Result;
use hex;
use rustc_serialize::hex::ToHex;

pub trait CoinCommonApdu: Default {
    fn select_applet() -> String;
    fn get_xpub(path: &str, verify_flag: bool) -> String;
    fn register_address(address: &[u8]) -> String;
}

pub struct BtcApdu();

impl Default for BtcApdu {
    fn default() -> Self {
        BtcApdu {}
    }
}

impl CoinCommonApdu for BtcApdu {
    fn select_applet() -> String {
        Apdu::select_applet(BTC_AID)
    }

    fn get_xpub(path: &str, verify_flag: bool) -> String {
        Apdu::get_pubkey(0x43, path, verify_flag)
    }

    fn register_address(address: &[u8]) -> String {
        Apdu::register_address(0x36, address)
    }
}

impl BtcApdu {
    pub fn btc_prepare(ins: u8, p1: u8, data: &Vec<u8>) -> Vec<String> {
        let mut apdu_vec = Vec::new();
        let apdu_number = (data.len() - 1) / LC_MAX as usize + 1;
        for index in 0..apdu_number {
            if index == apdu_number - 1 {
                let length = if data.len() % LC_MAX as usize == 0 {
                    LC_MAX
                } else {
                    (data.len() % LC_MAX as usize) as u32
                };
                let mut temp_apdu_vec =
                    ApduHeader::new(0x80, ins, p1, 0x80, length as u8).to_array();
                temp_apdu_vec.extend_from_slice(&data[index * LC_MAX as usize..]);
                apdu_vec.push(hex::encode_upper(temp_apdu_vec));
            } else {
                let mut temp_apdu_vec =
                    ApduHeader::new(0x80, ins, p1, 0x00, LC_MAX as u8).to_array();
                temp_apdu_vec.extend_from_slice(
                    &data[index * LC_MAX as usize..((index + 1) * LC_MAX as usize) as usize],
                );
                apdu_vec.push(hex::encode_upper(temp_apdu_vec));
            }
        }
        return apdu_vec;
    }

    pub fn btc_perpare_input(p1: u8, data: &Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x41, p1, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn btc_sign(index: u8, hash_type: u8, path: &str) -> String {
        let path_bytes = path.as_bytes();
        let mut apdu =
            ApduHeader::new(0x80, 0x42, index, hash_type, path_bytes.len() as u8).to_array();
        apdu.extend(path_bytes.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn btc_segwit_sign(last_one: bool, hash_type: u8, data: Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }

        let mut apdu = match last_one {
            true => ApduHeader::new(0x80, 0x32, 0x80, hash_type, data.len() as u8).to_array(),
            _ => ApduHeader::new(0x80, 0x32, 0x00, hash_type, data.len() as u8).to_array(),
        };

        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn omni_prepare_data(p1: u8, data: Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x44, p1, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn register_name_address(name: &[u8], address: &[u8]) -> String {
        let mut data: Vec<u8> = vec![];
        data.push(address.len() as u8);
        data.extend(address);
        data.push(name.len() as u8);
        data.extend(name);
        Apdu::register_address(0x37, &data)
    }
}

pub struct EthApdu();

impl Default for EthApdu {
    fn default() -> Self {
        EthApdu()
    }
}

impl CoinCommonApdu for EthApdu {
    fn select_applet() -> String {
        Apdu::select_applet(ETH_AID)
    }

    fn get_xpub(path: &str, verify_flag: bool) -> String {
        Apdu::get_pubkey(0x53, path, verify_flag)
    }

    fn register_address(address: &[u8]) -> String {
        Apdu::register_address(0x56, address)
    }
}

impl EthApdu {
    pub fn prepare_sign(data: Vec<u8>) -> Vec<String> {
        Apdu::prepare_sign(0x51, data)
    }

    pub fn sign_digest(path: &str) -> String {
        Apdu::sign_digest(0x52, 0x00, 0x00, path)
    }

    pub fn prepare_personal_sign(data: Vec<u8>) -> Vec<String> {
        Apdu::prepare_sign(0x54, data)
    }

    pub fn personal_sign(path: &str) -> String {
        Apdu::sign_digest(0x55, 0x00, 0x00, path)
    }
}

pub struct EosApdu();

impl Default for EosApdu {
    fn default() -> Self {
        EosApdu()
    }
}

impl CoinCommonApdu for EosApdu {
    fn select_applet() -> String {
        Apdu::select_applet(EOS_AID)
    }

    fn get_xpub(path: &str, verify_flag: bool) -> String {
        Apdu::get_pubkey(0x63, path, verify_flag)
    }

    fn register_address(address: &[u8]) -> String {
        Apdu::register_address(0x66, address)
    }
}

impl EosApdu {
    pub fn prepare_sign(data: Vec<u8>) -> Vec<String> {
        Apdu::prepare_sign(0x61, data)
    }

    pub fn sign_digest(path: &str) -> String {
        Apdu::sign_digest(0x52, 0x00, 0x00, path)
    }

    pub fn sign_tx(nonce: usize) -> String {
        let mut apdu = ApduHeader::new(0x80, 0x62, 0x00, 0x00, 0x02).to_array();
        apdu.push(((nonce & 0xFF00) >> 8) as u8);
        apdu.push((nonce & 0x00FF) as u8);
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn prepare_message_sign(data: Vec<u8>) -> Vec<String> {
        Apdu::prepare_sign(0x64, data)
    }

    pub fn sign_message(nonce: usize) -> String {
        let mut apdu = ApduHeader::new(0x80, 0x65, 0x00, 0x00, 0x02).to_array();
        apdu.push(((nonce & 0xFF00) >> 8) as u8);
        apdu.push((nonce & 0x00FF) as u8);
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }
}

pub struct CosmosApdu();

impl Default for CosmosApdu {
    fn default() -> Self {
        CosmosApdu()
    }
}

impl CoinCommonApdu for CosmosApdu {
    fn select_applet() -> String {
        Apdu::select_applet(COSMOS_AID)
    }

    fn get_xpub(path: &str, verify_flag: bool) -> String {
        Apdu::get_pubkey(0x73, path, verify_flag)
    }

    fn register_address(address: &[u8]) -> String {
        Apdu::register_address(0x76, address)
    }
}

impl CosmosApdu {
    pub fn prepare_sign(data: Vec<u8>) -> Vec<String> {
        Apdu::prepare_sign(0x71, data)
    }

    pub fn sign_digest(path: &str) -> String {
        Apdu::sign_digest(0x72, 0x00, 0x00, path)
    }
}

pub struct Secp256k1Apdu();

impl Default for Secp256k1Apdu {
    fn default() -> Self {
        Secp256k1Apdu()
    }
}

impl Secp256k1Apdu {
    pub fn sign(data: &[u8]) -> Vec<String> {
        Apdu::prepare_sign(0x81, data.to_vec())
    }

    pub fn get_xpub(data: &[u8]) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x82, 0x00, 0x00, data.len() as u8).to_array();
        apdu.extend(data);
        apdu.push(0x00); //Le
        hex::encode(apdu)
    }

    pub fn register_address(name: &[u8], address: &[u8]) -> String {
        let mut data: Vec<u8> = vec![];
        data.push(address.len() as u8);
        data.extend(address);
        data.push(name.len() as u8);
        data.extend(name);
        Apdu::register_address(0x83, &data)
    }
}

pub struct Ed25519Apdu();

impl Default for Ed25519Apdu {
    fn default() -> Self {
        Ed25519Apdu()
    }
}

impl Ed25519Apdu {
    pub fn sign(data: &[u8]) -> Vec<String> {
        Apdu::prepare_sign(0x81, data.to_vec())
    }

    pub fn get_xpub(data: &[u8]) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x82, 0x00, 0x00, data.len() as u8).to_array();
        apdu.extend(data);
        apdu.push(0x00); //Le
        hex::encode(apdu)
    }

    pub fn register_address(name: &[u8], address: &[u8]) -> String {
        let mut data: Vec<u8> = vec![];
        data.push(address.len() as u8);
        data.extend(address);
        data.push(name.len() as u8);
        data.extend(name);
        Apdu::register_address(0x83, &data)
    }
}

pub struct BtcForkApdu();

impl Default for BtcForkApdu {
    fn default() -> Self {
        BtcForkApdu {}
    }
}

impl CoinCommonApdu for BtcForkApdu {
    fn select_applet() -> String {
        Apdu::select_applet(BTC_AID)
    }

    fn get_xpub(path: &str, verify_flag: bool) -> String {
        Apdu::get_pubkey(0x43, path, verify_flag)
    }

    fn register_address(address: &[u8]) -> String {
        Apdu::register_address(0x36, address)
    }
}

impl BtcForkApdu {
    pub fn btc_fork_prepare(ins: u8, p1: u8, data: &Vec<u8>) -> Vec<String> {
        let mut apdu_vec = Vec::new();
        let apdu_number = (data.len() - 1) / LC_MAX as usize + 1;
        for index in 0..apdu_number {
            if index == apdu_number - 1 {
                let length = if data.len() % LC_MAX as usize == 0 {
                    LC_MAX
                } else {
                    (data.len() % LC_MAX as usize) as u32
                };
                let mut temp_apdu_vec =
                    ApduHeader::new(0x80, ins, p1, 0x80, length as u8).to_array();
                temp_apdu_vec.extend_from_slice(&data[index * LC_MAX as usize..]);
                apdu_vec.push(hex::encode_upper(temp_apdu_vec));
            } else {
                let mut temp_apdu_vec =
                    ApduHeader::new(0x80, ins, p1, 0x00, LC_MAX as u8).to_array();
                temp_apdu_vec.extend_from_slice(
                    &data[index * LC_MAX as usize..((index + 1) * LC_MAX as usize) as usize],
                );
                apdu_vec.push(hex::encode_upper(temp_apdu_vec));
            }
        }
        return apdu_vec;
    }

    pub fn btc_fork_perpare_input(ins: u8, p1: u8, data: &Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, ins, p1, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn btc_fork_sign(ins: u8, index: u8, hash_type: u8, path: &str) -> String {
        let path_bytes = path.as_bytes();
        let mut apdu =
            ApduHeader::new(0x80, ins, index, hash_type, path_bytes.len() as u8).to_array();
        apdu.extend(path_bytes.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn btc_fork_segwit_sign(ins: u8, last_one: bool, hash_type: u8, data: Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }

        let mut apdu = match last_one {
            true => ApduHeader::new(0x80, ins, 0x80, hash_type, data.len() as u8).to_array(),
            _ => ApduHeader::new(0x80, ins, 0x00, hash_type, data.len() as u8).to_array(),
        };

        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }
}

pub struct Apdu {}

struct ApduHeader {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    lc: u8,
}

impl ApduHeader {
    fn new(cla: u8, ins: u8, p1: u8, p2: u8, lc: u8) -> ApduHeader {
        ApduHeader {
            cla: cla,
            ins: ins,
            p1: p1,
            p2: p2,
            lc: lc,
        }
    }

    fn to_array(&self) -> Vec<u8> {
        vec![self.cla, self.ins, self.p1, self.p2, self.lc]
    }
}

impl Apdu {
    pub fn select_applet(aid: &str) -> String {
        let aid_array = hex::decode(aid).unwrap();
        let mut apdu = Vec::new();
        let apdu_header = ApduHeader::new(0x00, 0xA4, 0x04, 0x00, aid_array.len() as u8);
        apdu.extend(apdu_header.to_array().iter());
        apdu.extend(aid_array.iter());
        apdu.push(0x00); //Le
        hex::encode(apdu)
    }

    pub fn prepare_sign(ins: u8, data: Vec<u8>) -> Vec<String> {
        let mut apdu_list = Vec::new();
        let size = data.len() as u32 / LC_MAX as u32
            + if data.len() as u32 % LC_MAX as u32 != 0 {
                1
            } else {
                0
            };

        for i in 0..size {
            let mut apdu = Vec::new();
            let p1 = if i == 0 { 0x00 } else { 0x80 };
            let (p2, lc) = if i == size - 1 {
                (
                    0x80,
                    (data.len() as u32 - LC_MAX as u32 * (size - 1 as u32)) as u8,
                )
            } else {
                (0x00, 0xF5)
            };
            let apdu_header = ApduHeader::new(0x80, ins, p1, p2, lc);
            apdu.extend(apdu_header.to_array().iter());
            let payload =
                &data[(i as u32 * LC_MAX) as usize..(i as u32 * LC_MAX + lc as u32) as usize];
            apdu.extend(payload.iter()); //payload
            apdu.push(0x00); //le
            apdu_list.push(hex::encode(apdu))
        }
        apdu_list
    }

    pub fn get_pubkey(ins: u8, path: &str, verify_flag: bool) -> String {
        let path_bytes = path.as_bytes();
        if path_bytes.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let p1 = if verify_flag { 0x01 } else { 0x00 };
        let mut apdu = ApduHeader::new(0x80, ins, p1, 0x00, path_bytes.len() as u8).to_array();
        apdu.extend(path_bytes.iter());
        apdu.push(0x00); //Le
        hex::encode(apdu)
    }

    pub fn register_address(ins: u8, data: &[u8]) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, ins, 0x00, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    pub fn sign_digest(ins: u8, index: u8, hashtype: u8, path: &str) -> String {
        let path_bytes = path.as_bytes();
        if path_bytes.len() as u32 > LC_MAX {
            panic!("data to long");
        }

        let mut apdu = Vec::new();

        let apdu_header = ApduHeader::new(0x80, ins, index, hashtype, path_bytes.len() as u8);
        apdu.extend(apdu_header.to_array().iter());
        apdu.extend(path_bytes.iter()); //payload
        apdu.push(0x00); //le
        hex::encode(apdu)
    }

    pub fn set_ble_name(ble_name: &str) -> String {
        let ble_name_array = ble_name.as_bytes();
        let mut apdu = Vec::new();
        let apdu_header = ApduHeader::new(0xFF, 0xDA, 0x46, 0x54, ble_name_array.len() as u8);
        apdu.extend(apdu_header.to_array().iter());
        apdu.extend(ble_name_array.iter());
        apdu.push(0x00); //Le
        hex::encode(apdu)
    }
}

pub struct ImkApdu {}

impl ImkApdu {
    /**
    binding check apdu build
    */
    pub fn bind_check(data: &Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x71, 0x00, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }

    /**
    binding check apdu build
    */
    pub fn generate_auth_code() -> String {
        let apdu = ApduHeader::new(0x80, 0x72, 0x00, 0x00, 0x00).to_array();
        apdu.to_hex().to_uppercase()
    }

    /**
    bind code verify
    */
    pub fn identity_verify(data: &Vec<u8>) -> String {
        if data.len() as u32 > LC_MAX {
            panic!("data to long");
        }
        let mut apdu = ApduHeader::new(0x80, 0x73, 0x80, 0x00, data.len() as u8).to_array();
        apdu.extend(data.iter());
        apdu.push(0x00);
        apdu.to_hex().to_uppercase()
    }
}

pub struct ApduCheck {}

impl ApduCheck {
    pub fn check_response(response_data: &str) -> Result<()> {
        let response_data: &str = &response_data[response_data.len() - 4..];
        match response_data {
            "9000" => Ok(()),
            "6940" => Err(ApduError::ImkeyUserNotConfirmed.into()),
            "6985" => Err(ApduError::ImkeyConditionsNotSatisfied.into()),
            "6A82" => Err(ApduError::ImkeyAppletNotExist.into()),
            "6A86" => Err(ApduError::ImkeyCommandFormatError.into()),
            "6E00" => Err(ApduError::ImkeyCommandFormatError.into()),
            "6A80" => Err(ApduError::ImkeyCommandDataError.into()),
            "6700" => Err(ApduError::ImkeyApduWrongLength.into()),
            "6942" => Err(ApduError::ImkeySignatureVerifyFail.into()),
            "6D00" => Err(ApduError::ImkeyAppletFunctionNotSupported.into()),
            "6941" => Err(ApduError::ImkeyExceededMaxUtxoNumber.into()),
            "F000" => Err(ApduError::ImkeyWalletNotCreated.into()),
            "F080" => Err(ApduError::ImkeyInMenuPage.into()),
            "F081" => Err(ApduError::ImkeyPinNotVerified.into()),
            "6F01" => Err(ApduError::ImkeyBluetoothChannelError.into()),
            _ => Err(format_err!("imkey_command_execute_fail_{}", response_data)), //Err(ApduError::ImkeyCommandExecuteFail.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::apdu::{
        Apdu, ApduCheck, ApduHeader, BtcApdu, CoinCommonApdu, CosmosApdu, EosApdu, EthApdu, ImkApdu,
    };
    use hex::FromHex;

    #[test]
    fn select_applet_test() {
        assert_eq!(
            BtcApdu::select_applet(),
            String::from("00a4040005695f62746300")
        );
        assert_eq!(
            EthApdu::select_applet(),
            String::from("00a4040005695f65746800")
        );
        assert_eq!(
            EosApdu::select_applet(),
            String::from("00a4040005695f656f7300")
        );
        assert_eq!(
            CosmosApdu::select_applet(),
            String::from("00a4040008695f636f736d6f7300")
        );
        assert_eq!(
            Apdu::select_applet("695F696D6B"),
            String::from("00a4040005695f696d6b00")
        );
        assert_eq!(
            Apdu::select_applet("695F66696C65636F696E"),
            String::from("00a404000a695f66696c65636f696e00")
        );
    }

    #[test]
    fn get_xpub_test() {
        let path = String::from("m/44/0/0");
        let verify_flag = false;
        assert_eq!(
            BtcApdu::get_xpub(&path, verify_flag),
            String::from("80430000086d2f34342f302f3000")
        );
    }

    #[test]
    #[should_panic]
    fn register_address_test() {
        assert_eq!(
            BtcApdu::register_address("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g".as_bytes()),
            String::from(
                "803600002231327A36557A734133746A706165757641325A72396A77783139417A7A373444366700"
            )
        );
        assert_eq!(
            BtcApdu::register_address("37E2J9ViM4QFiewo7aw5L3drF2QKB99F9e".as_bytes()),
            String::from(
                "8036000022333745324A3956694D3451466965776F376177354C3364724632514B42393946396500"
            )
        );
        assert_eq!(
            EthApdu::register_address("0x6031564e7b2F5cc33737807b2E58DaFF870B590b".as_bytes()),
            String::from("805600002A30783630333135363465376232463563633333373337383037623245353844614646383730423539306200")
        );
        assert_eq!(
            EosApdu::register_address("EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF".as_bytes()),
            String::from("8066000035454F533838586869695037437535546D41554A71486279756879596764367365693638415532363650796574444441746A6D59574600")
        );
        assert_eq!(
            CosmosApdu::register_address("cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992".as_bytes()),
            String::from("807600002D636F736D6F7331616A7A397930783377656B657A37747A327464326A366C326466746E3238763236646439393200")
        );
        let long_address = hex::decode("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        Apdu::register_address(0x36, long_address.as_slice());
    }

    #[test]
    fn btc_prepare_test() {
        let data = Vec::from_hex("004630440220041038231F1C5E8D98EF941347BD9B6C220578128677BD561D258EC9B4CDFA3502203D18C43F7D06EE32D9527C8322F4D675F58856EC227ABF7085CCE65D5E5100C1019501000000040220D9AE2F000000001976A91455BDC1B42E3BED851959846DDF600E96125423E088AC0000000000000000536A4C500200000080A10BC28928F4C17A287318125115C3F098ED20A8237D1E8E4125BC25D1BE99752ADAD0A7B9CECA853768AEBB6965ECA126A62965F698A0C1BC43D83DB632AD7F717276057E6012AFA99385000000000100000000000000000027106F004630440220041038231F1C5E8D98EF941347BD9B6C220578128677BD561D258EC9B4CDFA3502203D18C43F7D06EE32D9527C8322F4D675F58856EC227ABF7085CCE65D5E5100C1019501000000040220D9AE2F000000001976A91455BDC1B42E3BED851959846DDF600E96125423E088AC0000000000000000536A4C500200000080A10BC28928F4C17A287318125115C3F098ED20A8237D1E8E4125BC25D1BE99752ADAD0A7B9CECA853768AEBB6965ECA126A62965F698A0C1BC43D83DB632AD7F717276057E6012AFA99385000000000100000000000000000027106F004630440220041038231F1C5E8D98EF941347BD9B6C220578128677BD561D258EC9B4CDFA3502203D18C43F7D06EE32D9527C8322F4D675F58856EC227ABF7085CCE65D5E5100C1019501000000040220D9AE2F000000001976A91455BDC1B42E3BED851959846DDF600E96125423E088AC0000000000000000536A4C500200000080A10BC28928F4C17A287318125115C3F098ED20A8237D1E8E4125BC25D1BE99752ADAD0A7B9CECA853768AEBB6965ECA126A62965F698A0C1BC43D83DB632AD7F717276057E6012AFA99385000000000100000000000000000027106F004630440220041038231F1C5E8D98EF941347BD9B6C220578128677BD561D258EC9B4CDFA3502203D18C43F7D06EE32D9527C8322F4D675F58856EC227ABF7085CCE65D5E5100C1019501000000040220D9AE2F000000001976A91455BDC1B42E3BED851959846DDF600E96125423E088AC0000000000000000536A4C500200000080A10BC28928F4C17A287318125115C3F098ED20A8237D1E8E4125BC25D1BE99752ADAD0A7B9CECA853768AEBB6965ECA126A62965F698A0C1BC43D83DB632AD7F717276057E6012AFA99385000000000100000000000000000027106F").unwrap();
        let apdu_vec = BtcApdu::btc_prepare(0x41, 0x00, &data);
        for apdu in apdu_vec {
            println!("apdu-->{:?}", apdu);
        }
    }

    #[test]
    #[should_panic]
    fn btc_perpare_input_test() {
        let data = Vec::from_hex("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        assert_eq!(
            BtcApdu::btc_perpare_input(0x80, &data),
            String::from("80418000427A222FB053B6E5339A9B6F9649F88A9481606CF3C64C4557802B3A819DDF3A98000000001976A914A189F2F7836812AA7A0E36E28A20A10E64010BF688ACFFFFFFFF00")
        );
        let long_data = Vec::from_hex("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        BtcApdu::btc_perpare_input(0x80, &long_data);
    }

    #[test]
    fn btc_sign_test() {
        assert_eq!(
            BtcApdu::btc_sign(02, 01, "m/44'/0'/0'/0/0"),
            String::from("804202010F6D2F3434272F30272F30272F302F3000")
        );
    }

    #[test]
    #[should_panic]
    fn btc_segwit_sign_test() {
        let data = Vec::from_hex("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec2000000001976a914654fbb08267f3d50d715a8f1abb55979b160dd5b88ac50c3000000000000ffffffffd622ad82d85a944f2c242762292e13462240fddd7d19791829e911d7885dec770000000001000000").unwrap();
        assert_eq!(
            BtcApdu::btc_segwit_sign(true, 01, data),
            String::from("80328001B60200000080A10BC28928F4C17A287318125115C3F098ED20A8237D1E8E4125BC25D1BE99752ADAD0A7B9CECA853768AEBB6965ECA126A62965F698A0C1BC43D83DB632AD7F717276057E6012AFA99385C18CC692397A666560520577679BF38C08B5CEC2000000001976A914654FBB08267F3D50D715A8F1ABB55979B160DD5B88AC50C3000000000000FFFFFFFFD622AD82D85A944F2C242762292E13462240FDDD7D19791829E911D7885DEC77000000000100000000")
        );
        let long_data = Vec::from_hex("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        BtcApdu::btc_segwit_sign(true, 01, long_data);
    }

    #[test]
    #[should_panic]
    fn omni_prepare_data_test() {
        let data = Vec::from_hex("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        assert_eq!(
            BtcApdu::omni_prepare_data(0x00, data),
            String::from("80440000427A222FB053B6E5339A9B6F9649F88A9481606CF3C64C4557802B3A819DDF3A98000000001976A914A189F2F7836812AA7A0E36E28A20A10E64010BF688ACFFFFFFFF00")
        );
        let long_data = Vec::from_hex("7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff7a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff").unwrap();
        BtcApdu::omni_prepare_data(0x00, long_data);
    }

    #[test]
    fn eth_personal_sign_test() {
        assert_eq!(
            EthApdu::personal_sign("m/44'/60'/0'/0/0"),
            String::from("80550000106d2f3434272f3630272f30272f302f3000")
        );
    }

    #[test]
    fn eth_get_xpub_test() {
        assert_eq!(
            EthApdu::get_xpub("m/44'/60'/0'/0/0", true),
            "80530100106d2f3434272f3630272f30272f302f3000"
        );
    }

    #[test]
    fn eth_sign_digest_test() {
        assert_eq!(
            EthApdu::sign_digest("m/44'/60'/0'/0/0"),
            String::from("80520000106d2f3434272f3630272f30272f302f3000")
        );
    }

    #[test]
    fn eth_prepare_personal_sign_test() {
        let data = Vec::from_hex("11223344556677889900").unwrap();
        let apdu_vec = EthApdu::prepare_personal_sign(data);
        for apdu in apdu_vec {
            assert_eq!(apdu, String::from("805400800a1122334455667788990000"));
        }
    }

    #[test]
    fn eth_prepare_sign_test() {
        let data = Vec::from_hex(
            "E4088504A817C8088302E24894353535353535353535353535353535353535353582020080",
        )
        .unwrap();
        let apdu_vec = EthApdu::prepare_sign(data);
        for apdu in apdu_vec {
            assert_eq!(
                apdu,
                String::from("8051008025e4088504a817c8088302e2489435353535353535353535353535353535353535358202008000")
            );
        }
    }

    #[test]
    fn eos_get_xpub_test() {
        assert_eq!(
            EthApdu::get_xpub("m/44'/194'/0'/0/0", true),
            "80530100116d2f3434272f313934272f30272f302f3000"
        );
    }

    #[test]
    fn eos_prepare_sign_test() {
        let data = Vec::from_hex("00044CABB9DB0704786D746F0806786D66726F6D09063132333435360120B998C88D8478E87E6DEE727ADECEC067A3201DA03EC8F8E8861C946559BE635505116D2F3434272F313934272F30272F302F30").unwrap();
        let apdu_vec = EosApdu::prepare_sign(data);
        for apdu in apdu_vec {
            assert_eq!(
                apdu,
                String::from("806100805100044cabb9db0704786d746f0806786d66726f6d09063132333435360120b998c88d8478e87e6dee727adecec067a3201da03ec8f8e8861c946559be635505116d2f3434272f313934272f30272f302f3000")
            );
        }
    }

    #[test]
    fn eos_sign_digest_test() {
        assert_eq!(
            EosApdu::sign_digest("m/44'/194'/0'/0/0"),
            String::from("80520000116d2f3434272f313934272f30272f302f3000")
        );
    }

    #[test]
    fn eos_sign_tx_test() {
        assert_eq!(EosApdu::sign_tx(0101), "8062000002006500".to_string());
    }

    #[test]
    fn eos_prepare_message_sign_test() {
        let data = Vec::from_hex("11223344556677889900").unwrap();
        let apdu_vec = EosApdu::prepare_message_sign(data);
        for apdu in apdu_vec {
            assert_eq!(apdu, String::from("806400800a1122334455667788990000"));
        }
    }

    #[test]
    fn eos_sign_message_test() {
        assert_eq!(EosApdu::sign_message(1), String::from("8065000002000100"));
    }

    #[test]
    fn cosmos_get_xpub_test() {
        assert_eq!(
            CosmosApdu::get_xpub("m/44'/118'/0'/0/0", true),
            "80730100116d2f3434272f313138272f30272f302f3000"
        );
    }

    #[test]
    fn cosmos_prepare_sign_test() {
        let data = Vec::from_hex("0046304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D").unwrap();
        let apdu_vec = CosmosApdu::prepare_sign(data);
        for apdu in apdu_vec {
            assert_eq!(
                apdu,
                String::from("80710080b30046304402204c6301e02c4b37d7828d6f20ca6406eb0afadbebb1c563baaa371982eab8be5e02204a12558fea32093e7175fa022919f1067194e542a78f8c2fe1138a4a0750d866012090260fea755e8ca08f6df4506f64fdbb5b806a5706c51ff056c76f05111794ac070a302e3030312041544f4d082d636f736d6f73317965636b787a377461707a33346b6a776e6a78766d787a7572657271756874726d786d757874090c302e30303037352061746f6d00")
            );
        }
    }

    #[test]
    fn cosmos_sign_digest_test() {
        assert_eq!(
            CosmosApdu::sign_digest("m/44'/118'/0'/0/0"),
            String::from("80720000116d2f3434272f313138272f30272f302f3000")
        );
    }

    #[test]
    #[should_panic]
    fn bind_check_test() {
        let data = Vec::from_hex("304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D").unwrap();
        assert_eq!(
            ImkApdu::bind_check(&data),
            String::from("80710000B1304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D00")
        );
        let long_data = Vec::from_hex("304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6DD082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D74090C302E30303037352061746F6D74090C302E30303037352061746F6D").unwrap();
        ImkApdu::bind_check(&long_data);
    }

    #[test]
    fn generate_auth_code_test() {
        assert_eq!(ImkApdu::generate_auth_code(), String::from("8072000000"));
    }

    #[test]
    #[should_panic]
    fn identity_verify_test() {
        let data = Vec::from_hex("304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D").unwrap();
        assert_eq!(
            ImkApdu::identity_verify(&data),
            String::from("80738000B1304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D00")
        );
        let long_data = Vec::from_hex("304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D304402204C6301E02C4B37D7828D6F20CA6406EB0AFADBEBB1C563BAAA371982EAB8BE5E02204A12558FEA32093E7175FA022919F1067194E542A78F8C2FE1138A4A0750D866012090260FEA755E8CA08F6DF4506F64FDBB5B806A5706C51FF056C76F05111794AC070A302E3030312041544F4D082D636F736D6F73317965636B787A377461707A33346B6A776E6A78766D787A7572657271756874726D786D757874090C302E30303037352061746F6D").unwrap();
        ImkApdu::identity_verify(&long_data);
    }

    #[test]
    fn apdu_header_test() {
        assert_eq!(
            ApduHeader::new(0x00, 0xA4, 0x04, 0x00, 0x00).to_array(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x00]
        );
    }

    #[test]
    #[should_panic]
    fn apdu_get_xpub() {
        let long_path = "m/44'/60'/0'/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0";
        Apdu::get_pubkey(0x43, long_path, true);
    }

    #[test]
    #[should_panic]
    fn apdu_sign_digest_test() {
        let long_path = "m/44'/60'/0'/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0";
        Apdu::sign_digest(0x52, 0x00, 0x00, long_path);
    }

    #[test]
    fn apdu_set_ble_name_test() {
        assert_eq!(
            Apdu::set_ble_name("helloimkey"),
            "ffda46540a68656c6c6f696d6b657900"
        );
    }

    #[test]
    fn check_response_test() {
        assert!(ApduCheck::check_response("009000").is_ok());
        assert!(ApduCheck::check_response("006940").is_err());
        assert!(ApduCheck::check_response("006985").is_err());
        assert!(ApduCheck::check_response("006280").is_err());
        assert!(ApduCheck::check_response("006A86").is_err());
        assert!(ApduCheck::check_response("006E00").is_err());
        assert!(ApduCheck::check_response("006A80").is_err());
        assert!(ApduCheck::check_response("006700").is_err());
        assert!(ApduCheck::check_response("006942").is_err());
        assert!(ApduCheck::check_response("006D00").is_err());
        assert!(ApduCheck::check_response("006941").is_err());
        assert!(ApduCheck::check_response("00F000").is_err());
        assert!(ApduCheck::check_response("00F080").is_err());
        assert!(ApduCheck::check_response("00F081").is_err());
        assert!(ApduCheck::check_response("006F01").is_err());
        assert!(ApduCheck::check_response("000000").is_err());
    }
}
