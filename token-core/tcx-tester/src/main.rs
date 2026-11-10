use bytes::BytesMut;
use prost::Message;
use std::env;
use std::ffi::CString;
use tcx::api::InitTokenCoreXParam;
use tcx::{call_tcx_api, free_const_string, get_last_err_message};

pub fn encode_message(msg: impl Message) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).unwrap();
    buf.to_vec()
}

fn main() {
    let param = InitTokenCoreXParam {
        file_dir: "/tmp/imtoken/wallets".to_string(),
        xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
        xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
        is_debug: true,
    };

    // let hex_str = hex::encode(encode_message(param))
    tcx::handler::init_token_core_x(&encode_message(param)).unwrap();

    let args: Vec<String> = env::args().collect();
    let hex = &args[1];
    // let bytes = Vec::from_hex(hex).expect("decode hex");
    // let param_buf = wrap_buffer(bytes);
    let request = CString::new(hex.as_str()).unwrap();
    unsafe {
        let response = call_tcx_api(request.as_ptr());
        let error = get_last_err_message();
        free_const_string(response);
        free_const_string(error);
    }
}
