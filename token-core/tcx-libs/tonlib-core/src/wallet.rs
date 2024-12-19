mod types;

use std::sync::Arc;

pub use types::*;

use crate::cell::{ArcCell, BagOfCells, Cell, TonCellError};

pub const DEFAULT_WALLET_ID_V5R1: i32 = 0x7FFFFF11;
pub const DEFAULT_WALLET_ID: i32 = 0x29a9a317;

pub const WALLET_V1R1_CODE: &str = "te6cckEBAQEARAAAhP8AIN2k8mCBAgDXGCDXCx/tRNDTH9P/0VESuvKhIvkBVBBE+RDyovgAAdMfMSDXSpbTB9QC+wDe0aTIyx/L/8ntVEH98Ik=";
pub const WALLET_V1R2_CODE: &str = "te6cckEBAQEAUwAAov8AIN0gggFMl7qXMO1E0NcLH+Ck8mCBAgDXGCDXCx/tRNDTH9P/0VESuvKhIvkBVBBE+RDyovgAAdMfMSDXSpbTB9QC+wDe0aTIyx/L/8ntVNDieG8=";
pub const WALLET_V1R3_CODE: &str = "te6cckEBAQEAXwAAuv8AIN0gggFMl7ohggEznLqxnHGw7UTQ0x/XC//jBOCk8mCBAgDXGCDXCx/tRNDTH9P/0VESuvKhIvkBVBBE+RDyovgAAdMfMSDXSpbTB9QC+wDe0aTIyx/L/8ntVLW4bkI=";
pub const WALLET_V2R1_CODE: &str = "te6cckEBAQEAVwAAqv8AIN0gggFMl7qXMO1E0NcLH+Ck8mCDCNcYINMf0x8B+CO78mPtRNDTH9P/0VExuvKhA/kBVBBC+RDyovgAApMg10qW0wfUAvsA6NGkyMsfy//J7VShNwu2";
pub const WALLET_V2R2_CODE: &str = "te6cckEBAQEAYwAAwv8AIN0gggFMl7ohggEznLqxnHGw7UTQ0x/XC//jBOCk8mCDCNcYINMf0x8B+CO78mPtRNDTH9P/0VExuvKhA/kBVBBC+RDyovgAApMg10qW0wfUAvsA6NGkyMsfy//J7VQETNeh";
pub const WALLET_V3R1_CODE: &str = "te6cckEBAQEAYgAAwP8AIN0gggFMl7qXMO1E0NcLH+Ck8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVD++buA=";
pub const WALLET_V3R2_CODE: &str = "te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0=";
pub const WALLET_V4R1_CODE: &str = "te6cckECFQEAAvUAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyY+1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8REhMUA+7QAdDTAwFxsJFb4CHXScEgkVvgAdMfIYIQcGx1Z70ighBibG5jvbAighBkc3RyvbCSXwPgAvpAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8F4ATTP8glghBwbHVnupEx4w0kghBibG5juuMABAYHCAIBIAkKAFAB+gD0BDCCEHBsdWeDHrFwgBhQBcsFJ88WUAP6AvQAEstpyx9SEMs/AFL4J28ighBibG5jgx6xcIAYUAXLBSfPFiT6AhTLahPLH1Iwyz8B+gL0AACSghBkc3Ryuo41BIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UghBkc3Rygx6xcIAYUATLBVjPFiL6AhLLassfyz+UEDRfBOLJgED7AAIBIAsMAFm9JCtvaiaECAoGuQ+gIYRw1AgIR6STfSmRDOaQPp/5g3gSgBt4EBSJhxWfMYQCAVgNDgARuMl+1E0NcLH4AD2ynftRNCBAUDXIfQEMALIygfL/8nQAYEBCPQKb6ExgAgEgDxAAGa3OdqJoQCBrkOuF/8AAGa8d9qJoQBBrkOuFj8AAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJcfsAyEAUgQEI9FHypwIAbIEBCNcYyFQgJYEBCPRR8qeCEG5vdGVwdIAYyMsFywJQBM8WghAF9eEA+gITy2oSyx/JcfsAAgBygQEI1xgwUgKBAQj0WfKn+CWCEGRzdHJwdIAYyMsFywJQBc8WghAF9eEA+gIUy2oTyx8Syz/Jc/sAAAr0AMntVEap808=";
pub const WALLET_V4R2_CODE: &str = "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVGliJeU=";
pub const WALLET_V5R1_CODE: &str = "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=";
pub const HIGHLOAD_V1R1_CODE: &str = "te6ccgEBBgEAhgABFP8A9KQT9KDyyAsBAgEgAgMCAUgEBQC88oMI1xgg0x/TH9Mf+CMTu/Jj7UTQ0x/TH9P/0VEyuvKhUUS68qIE+QFUEFX5EPKj9ATR+AB/jhghgBD0eG+hb6EgmALTB9QwAfsAkTLiAbPmWwGkyMsfyx/L/8ntVAAE0DAAEaCZL9qJoa4WPw==";
pub const HIGHLOAD_V1R2_CODE: &str = "te6ccgEBCAEAmQABFP8A9KQT9LzyyAsBAgEgAgMCAUgEBQC88oMI1xgg0x/TH9Mf+CMTu/Jj7UTQ0x/TH9P/0VEyuvKhUUS68qIE+QFUEFX5EPKj9ATR+AB/jhghgBD0eG+hb6EgmALTB9QwAfsAkTLiAbPmWwGkyMsfyx/L/8ntVAAE0DACAUgGBwAXuznO1E0NM/MdcL/4ABG4yX7UTQ1wsfg=";
pub const HIGHLOAD_V2_CODE: &str = "te6ccgEBCQEA5QABFP8A9KQT9LzyyAsBAgEgAgcCAUgDBAAE0DACASAFBgAXvZznaiaGmvmOuF/8AEG+X5dqJoaY+Y6Z/p/5j6AmipEEAgegc30JjJLb/JXdHxQB6vKDCNcYINMf0z/4I6ofUyC58mPtRNDTH9M/0//0BNFTYIBA9A5voTHyYFFzuvKiB/kBVBCH+RDyowL0BNH4AH+OFiGAEPR4b6UgmALTB9QwAfsAkTLiAbPmW4MlochANIBA9EOK5jEByMsfE8s/y//0AMntVAgANCCAQPSWb6VsEiCUMFMDud4gkzM2AZJsIeKz";
pub const HIGHLOAD_V2R1_CODE: &str = "te6ccgEBCQEA6QABFP8A9KQT9LzyyAsBAgEgAgMCAUgEBQHu8oMI1xgg0x/TP/gjqh9TILnyY+1E0NMf0z/T//QE0VNggED0Dm+hMfJgUXO68qIH+QFUEIf5EPKjAvQE0fgAf44YIYAQ9HhvoW+hIJgC0wfUMAH7AJEy4gGz5luDJaHIQDSAQPRDiuYxyBLLHxPLP8v/9ADJ7VQIAATQMAIBIAYHABe9nOdqJoaa+Y64X/wAQb5fl2omhpj5jpn+n/mPoCaKkQQCB6BzfQmMktv8ld0fFAA4IIBA9JZvoW+hMlEQlDBTA7neIJMzNgGSMjDisw==";
pub const HIGHLOAD_V2R2_CODE: &str = "te6ccgEBCQEA6QABFP8A9KQT9LzyyAsBAgEgAgMCAUgEBQHu8oMI1xgg0x/TP/gjqh9TILnyY+1E0NMf0z/T//QE0VNggED0Dm+hMfJgUXO68qIH+QFUEIf5EPKjAvQE0fgAf44YIYAQ9HhvoW+hIJgC0wfUMAH7AJEy4gGz5luDJaHIQDSAQPRDiuYxyBLLHxPLP8v/9ADJ7VQIAATQMAIBIAYHABe9nOdqJoaa+Y64X/wAQb5fl2omhpj5jpn+n/mPoCaKkQQCB6BzfQmMktv8ld0fFAA4IIBA9JZvoW+hMlEQlDBTA7neIJMzNgGSMjDisw==";

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
    pub fn code(&self) -> Result<ArcCell, TonCellError> {
        let code = match self {
            WalletVersion::V1R1 => WALLET_V1R1_CODE,
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
        let bag_of_cells = BagOfCells::parse_base64(code).expect("ton_parse_base64_error");
        let cell = bag_of_cells.single_root()?;
        Ok(cell.clone())
    }

    pub fn initial_data(&self, key: &[u8], wallet_id: i32) -> Result<ArcCell, TonCellError> {
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

    pub fn from_code(code: &str) -> Result<WalletVersion, TonCellError> {
        let wallet_version = match code {
            WALLET_V1R3_CODE => WalletVersion::V1R3,
            WALLET_V2R1_CODE => WalletVersion::V2R1,
            WALLET_V2R2_CODE => WalletVersion::V2R2,
            WALLET_V3R1_CODE => WalletVersion::V3R1,
            WALLET_V3R2_CODE => WalletVersion::V3R2,
            WALLET_V4R1_CODE => WalletVersion::V4R1,
            WALLET_V4R2_CODE => WalletVersion::V4R2,
            WALLET_V5R1_CODE => WalletVersion::V5R1,
            HIGHLOAD_V1R1_CODE => WalletVersion::HighloadV1R1,
            HIGHLOAD_V1R2_CODE => WalletVersion::HighloadV1R2,
            HIGHLOAD_V2R2_CODE => WalletVersion::HighloadV2R2,
            _ => return Err(TonCellError::InvalidInitCode(code.to_string())),
        };

        Ok(wallet_version)
    }
}
