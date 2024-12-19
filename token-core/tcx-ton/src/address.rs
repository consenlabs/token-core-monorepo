use core::str::FromStr;
use tcx_common::ToHex;
use tcx_constants::CoinInfo;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;
use tonlib_core::{
    cell::StateInit,
    types::TonAddress as TonAddressLib,
    wallet::{WalletVersion, DEFAULT_WALLET_ID, DEFAULT_WALLET_ID_V5R1},
};

#[derive(PartialEq, Eq, Clone)]
pub struct TonAddress(String);

impl Address for TonAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let wallet_version = WalletVersion::from_code(&coin.contract_code)?;

        let wallet_id = match wallet_version {
            WalletVersion::V5R1 => DEFAULT_WALLET_ID_V5R1,
            _ => DEFAULT_WALLET_ID,
        };

        let non_production = match coin.network.as_str() {
            "TESTNET" => true,
            _ => false,
        };

        let data = wallet_version.initial_data(&public_key.to_bytes(), wallet_id)?;
        let code = wallet_version.code()?;
        let state_init_hash = StateInit::create_account_id(&code, &data)?;

        let addr = TonAddressLib::new(0, &state_init_hash);
        //true:Non-bounceable false:Bounceable
        let address = addr.to_base64_url_flags(true, non_production);

        Ok(TonAddress(address))
    }

    fn is_valid(address: &str, coin: &CoinInfo) -> bool {
        let result = TonAddressLib::from_base64_std_flags(address);
        if let Ok(ton_addr) = result {
            if (ton_addr.2 && coin.network.eq_ignore_ascii_case("TESTNET"))
                || (!ton_addr.2 && coin.network.eq_ignore_ascii_case("MAINNET"))
            {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl FromStr for TonAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(TonAddress(s.to_string()))
    }
}

impl ToString for TonAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
mod test {
    use tcx_constants::{CoinInfo, CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{HdKeystore, Keystore, Metadata};

    #[test]
    fn test_ton_address() {
        let hd =
            HdKeystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();

        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: "m/44'/607'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            //V5R1 code
            contract_code: "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=".to_string(),
        };

        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "0QDBKGsYs49NgdqM4gMoiVMV9Re5hM-yy3nvR_4XB0ZbUHzx",
            acc.address
        );

        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: "m/44'/607'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            //V5R1 code
            contract_code: "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=".to_string(),
        };

        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "UQDBKGsYs49NgdqM4gMoiVMV9Re5hM-yy3nvR_4XB0ZbUMd7",
            acc.address
        );

        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: "m/44'/607'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            //V4R2 code
            contract_code: "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVGliJeU=".to_string(),
        };

        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "0QAz8TQ4n_ktc--IpefK-d5ABVpTR-FciJgLZr9vUpEgaGxk",
            acc.address
        );

        let coin = CoinInfo {
            coin: "TON".to_string(),
            derivation_path: "m/44'/607'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            //V4R2 code
            contract_code: "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVGliJeU=".to_string(),
        };

        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "UQAz8TQ4n_ktc--IpefK-d5ABVpTR-FciJgLZr9vUpEgaNfu",
            acc.address
        );
    }
}
