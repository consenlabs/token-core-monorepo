mod types;

use std::sync::Arc;

use lazy_static::lazy_static;
pub use types::*;

use crate::cell::{ArcCell, BagOfCells, Cell, TonCellError};

pub const DEFAULT_WALLET_ID_V5R1: i32 = 0x7FFFFF11;
pub const DEFAULT_WALLET_ID: i32 = 0x29a9a317;

lazy_static! {
    pub static ref WALLET_V1R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v1r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V1R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v1r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V1R3_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v1r3.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V2R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v2r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V2R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v2r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V3R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v3r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V3R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v3r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V4R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v4r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V4R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v4r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref WALLET_V5R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/wallet_v5.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref HIGHLOAD_V1R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/highload_v1r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref HIGHLOAD_V1R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/highload_v1r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref HIGHLOAD_V2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/highload_v2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref HIGHLOAD_V2R1_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/highload_v2r1.code");
        BagOfCells::parse_base64(code).unwrap()
    };
    pub static ref HIGHLOAD_V2R2_CODE: BagOfCells = {
        let code = include_str!("../resources/wallet/highload_v2r2.code");
        BagOfCells::parse_base64(code).unwrap()
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum WalletVersion {
    V1R1,
    V1R2,
    V1R3,
    V2R1,
    V2R2,
    V3R1,
    V3R2,
    V4R1,
    V4R2,
    V5R1,
    HighloadV1R1,
    HighloadV1R2,
    HighloadV2,
    HighloadV2R1,
    HighloadV2R2,
}

impl WalletVersion {
    pub fn code(&self) -> Result<&ArcCell, TonCellError> {
        let code: &BagOfCells = match self {
            WalletVersion::V1R1 => &WALLET_V1R1_CODE,
            WalletVersion::V1R2 => &WALLET_V1R2_CODE,
            WalletVersion::V1R3 => &WALLET_V1R3_CODE,
            WalletVersion::V2R1 => &WALLET_V2R1_CODE,
            WalletVersion::V2R2 => &WALLET_V2R2_CODE,
            WalletVersion::V3R1 => &WALLET_V3R1_CODE,
            WalletVersion::V3R2 => &WALLET_V3R2_CODE,
            WalletVersion::V4R1 => &WALLET_V4R1_CODE,
            WalletVersion::V4R2 => &WALLET_V4R2_CODE,
            WalletVersion::V5R1 => &WALLET_V5R1_CODE,
            WalletVersion::HighloadV1R1 => &HIGHLOAD_V1R1_CODE,
            WalletVersion::HighloadV1R2 => &HIGHLOAD_V1R2_CODE,
            WalletVersion::HighloadV2 => &HIGHLOAD_V2_CODE,
            WalletVersion::HighloadV2R1 => &HIGHLOAD_V2R1_CODE,
            WalletVersion::HighloadV2R2 => &HIGHLOAD_V2R2_CODE,
        };
        code.single_root()
    }

    pub fn initial_data(&self, key: &[u8], wallet_id: i32) -> Result<ArcCell, TonCellError> {
        // let public_key: TonHash = key_pair
        //     .public_key
        //     .clone()
        //     .try_into()
        //     .map_err(|_| TonCellError::InternalError("Invalid public key size".to_string()))?;

        let mut public_key: [u8; 32] = [0; 32];
        public_key.copy_from_slice(&key.to_vec());
        let data_cell: Cell = match &self {
            WalletVersion::V1R1
            | WalletVersion::V1R2
            | WalletVersion::V1R3
            | WalletVersion::V2R1
            | WalletVersion::V2R2 => WalletDataV1V2 {
                seqno: 0,
                public_key,
            }
            .try_into()?,
            WalletVersion::V3R1 | WalletVersion::V3R2 => WalletDataV3 {
                seqno: 0,
                wallet_id,
                public_key,
            }
            .try_into()?,
            WalletVersion::V4R1 | WalletVersion::V4R2 => WalletDataV4 {
                seqno: 0,
                wallet_id,
                public_key,
            }
            .try_into()?,
            WalletVersion::V5R1 => WalletDataV5 {
                signature_allowed: true,
                seqno: 0,
                wallet_id,
                public_key,
            }
            .try_into()?,
            WalletVersion::HighloadV2R2 => WalletDataHighloadV2R2 {
                wallet_id,
                last_cleaned_time: 0,
                public_key,
            }
            .try_into()?,
            WalletVersion::HighloadV1R1
            | WalletVersion::HighloadV1R2
            | WalletVersion::HighloadV2
            | WalletVersion::HighloadV2R1 => {
                return Err(TonCellError::InternalError(
                    "No generation for this wallet version".to_string(),
                ));
            }
        };

        Ok(Arc::new(data_cell))
    }
}
