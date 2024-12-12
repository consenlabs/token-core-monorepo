use core::str::FromStr;
use tcx_common::ToHex;
use tcx_constants::CoinInfo;
use tcx_keystore::{Address, Result};
use tcx_primitive::TypedPublicKey;
use tonlib_core::{cell::StateInit, types::TonAddress as TonAddressLib, wallet::WalletVersion};

// size of address
pub const LENGTH: usize = 20;

#[derive(PartialEq, Eq, Clone)]
pub struct TonAddress(String);

impl Address for TonAddress {
    fn from_public_key(public_key: &TypedPublicKey, coin: &CoinInfo) -> Result<Self> {
        let pub_key_bytes = public_key.to_bytes();
        println!("{}", pub_key_bytes.clone().to_0x_hex());

        let wallet_id: i32 = 0x29a9a317;
        let wallet_version = WalletVersion::V4R2;
        let workchain = 0;

        let non_production = match coin.network.as_str() {
            "TESTNET" => true,
            _ => false,
        };

        let data = wallet_version.initial_data(&pub_key_bytes, wallet_id)?;
        let code = wallet_version.code()?;
        let state_init_hash = StateInit::create_account_id(code, &data)?;

        let addr = TonAddressLib::new(workchain, &state_init_hash);
        let address = addr.to_base64_std_flags(false, non_production);

        let result = TonAddressLib::from_base64_std_flags(&address)?;
        println!(
            "workchain: {},hash_path: {}",
            result.0.workchain,
            result.0.hash_part.as_slice().to_0x_hex()
        );
        println!("non_bounceable: {}", result.1);
        println!("non_production: {}", result.2);

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
        let coin = CoinInfo {
            coin: "TON".to_string(),
            // todo: the ton path is not official
            derivation_path: "m/44'/607'/0'".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
        };

        let mut keystore = Keystore::Hd(hd);
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        let acc = keystore
            .derive_coin::<crate::address::TonAddress>(&coin)
            .unwrap();
        assert_eq!(
            "EQCKJfmBlnFiINcL1MoCjuyxULXaOEA-k5iHcr4L18RuhQHo",
            acc.address
        );
    }
}
