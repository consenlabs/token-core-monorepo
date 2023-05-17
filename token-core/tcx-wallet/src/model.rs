// use std::time::{SystemTime, UNIX_EPOCH};
// use crate::Result;
//
// pub const FROM_MNEMONIC: &str = "MNEMONIC";
// pub const FROM_KEYSTORE: &str = "KEYSTORE";
// pub const FROM_PRIVATE: &str = "PRIVATE";
// pub const FROM_WIF: &str = "WIF";
// pub const FROM_NEW_IDENTITY: &str = "NEW_IDENTITY";
// pub const FROM_RECOVERED_IDENTITY: &str = "RECOVERED_IDENTITY";
// pub const P2WPKH: &str = "P2WPKH";
// pub const NONE: &str = "NONE";
// pub const NORMAL: &str = "NORMAL";
// pub const HD: &str = "HD";
// pub const RANDOM: &str = "RANDOM";
// pub const HD_SHA256: &str = "HD_SHA256";
// pub const V3: &str = "V3";
//
// struct Metadata{
//     name: String,
//     password_hint: String,
//     chain_type: String,
//     timestamp: String,
//     network: String,
//     source: Option<String>,
//     mode: Option<String>,
//     wallet_type: Option<String>,
//     segWit: Option<String>,
// }
//
// impl Metadata{
//     fn new(&self, name: &str, password_hint: &str, chain_type: &str, network: &str, seg_wit: Option<&str>)-> Result<Self>{
//         let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
//         let temp_seg_wit = if let Some(a) = seg_wit {
//             Some(a.to_string())
//         }else{
//           None
//         };
//         Ok(Metadata{
//             name: name.to_string(),
//             password_hint: password_hint.to_string(),
//             chain_type: chain_type.to_string(),
//             timestamp: "test".to_string(),
//             network: network.to_string(),
//             source: None,
//             mode: None,
//             wallet_type: None,
//             segWit: temp_seg_wit,
//         })
//     }
// }
