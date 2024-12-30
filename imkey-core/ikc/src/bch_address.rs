use crate::api::{AddressParam, BtcForkWallet};
use crate::error_handling::Result;
use crate::message_handler::encode_message;
use coin_bch::address::BchAddress;
use coin_btc_fork::address::BtcForkAddress;
use ikc_common::path::get_account_path;
use ikc_common::utility::network_convert;

pub fn get_address(param: &AddressParam) -> Result<Vec<u8>> {
    let network = network_convert(param.network.as_ref());
    let address = BchAddress::get_address(network, &param.path)?;
    let account_path = get_account_path(&param.path)?;
    let enc_xpub = BtcForkAddress::get_enc_xpub(network, &account_path)?;

    let address_message = BtcForkWallet {
        path: param.path.to_owned(),
        chain_type: param.chain_type.to_string(),
        address: address,
        enc_x_pub: enc_xpub,
    };

    encode_message(address_message)
}

#[cfg(test)]
mod tests {
    use crate::api::AddressParam;
    use crate::bch_address::get_address;
    use ikc_device::device_binding::bind_test;

    #[test]
    fn test_btc_fork_address() {
        bind_test();

        let param = AddressParam {
            chain_type: "BITCOINCASH".to_string(),
            path: "m/44'/145'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            contract_code: "".to_string(),
        };
        let message = get_address(&param);
        assert_eq!("0a116d2f3434272f313435272f30272f302f30120b424954434f494e434153481a2a717a6c643764617637643273666a646c367839736e6b76663672616a386c66786a636a3566613879327222980177414b55655236664f47464c2b76693530562b4d645653483538674c79384a78377a537879777a30744e2b2b6c324530554e47377a762b52314656676e727155366430776c363939512f49374f36313855785337676e7046786b47754b3073494434666937704766396169764678754b792f37414a4a366b4f6d584831527a3646435336623857374e4b6c7a6762635a704a6d4473513d3d", hex::encode(message.unwrap()));

        let param = AddressParam {
            chain_type: "BITCOINCASH".to_string(),
            path: "m/44'/145'/0'/0/0".to_string(),
            network: "TESTNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            contract_code: "".to_string(),
        };
        let message = get_address(&param);
        assert_eq!("0a116d2f3434272f313435272f30272f302f30120b424954434f494e434153481a2a717a6c643764617637643273666a646c367839736e6b76663672616a386c66786a636b786436396e646c2298014e747177634547676d506961382f4f4663616933676d7a794746646f3247306e436736574631545436556275727974636d7355324d727062447868497833396b46566f6f4d536b716267434f4f763564785370716e5154796649636d7a4a696b64786b6f2f79474f346a4a6d484d6e5a4247786f74377859716e6d38794d7330794a74314c7a65596a70683941576d48664d755550673d3d", hex::encode(message.unwrap()));
    }
}
