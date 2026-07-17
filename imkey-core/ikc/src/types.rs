#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Method {
    InitImkeyCoreX,
    ConfigureTsm,
    AppDownload,
    AppUpdate,
    AppDelete,
    DeviceActivate,
    CheckUpdate,
    DeviceSecureCheck,
    BindCheck,
    BindDisplayCode,
    BindAcquire,
    GetSeid,
    GetSn,
    GetRamSize,
    GetFirmwareVersion,
    GetBatteryPower,
    GetLifeTime,
    GetBleName,
    SetBleName,
    GetBleVersion,
    GetSdkInfo,
    CosUpdate,
    CosCheckUpdate,
    DeviceConnect,
    IsBlStatus,
    GetAddress,
    DeriveAccounts,
    DeriveSubAccounts,
    GetPublicKeys,
    RegisterPubKey,
    RegisterAddress,
    SignTx,
    SignMessage,
    CalcExternalAddress,
    GetExtendedPublicKeys,
    SignPsbt,
}

impl Method {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "init_imkey_core_x" => Self::InitImkeyCoreX,
            "configure_tsm" => Self::ConfigureTsm,
            "app_download" => Self::AppDownload,
            "app_update" => Self::AppUpdate,
            "app_delete" => Self::AppDelete,
            "device_activate" => Self::DeviceActivate,
            "check_update" => Self::CheckUpdate,
            "device_secure_check" => Self::DeviceSecureCheck,
            "bind_check" => Self::BindCheck,
            "bind_display_code" => Self::BindDisplayCode,
            "bind_acquire" => Self::BindAcquire,
            "get_seid" => Self::GetSeid,
            "get_sn" => Self::GetSn,
            "get_ram_size" => Self::GetRamSize,
            "get_firmware_version" => Self::GetFirmwareVersion,
            "get_battery_power" => Self::GetBatteryPower,
            "get_life_time" => Self::GetLifeTime,
            "get_ble_name" => Self::GetBleName,
            "set_ble_name" => Self::SetBleName,
            "get_ble_version" => Self::GetBleVersion,
            "get_sdk_info" => Self::GetSdkInfo,
            "cos_update" => Self::CosUpdate,
            "cos_check_update" => Self::CosCheckUpdate,
            "device_connect" => Self::DeviceConnect,
            "is_bl_status" => Self::IsBlStatus,
            "get_address" => Self::GetAddress,
            "derive_accounts" => Self::DeriveAccounts,
            "derive_sub_accounts" => Self::DeriveSubAccounts,
            "get_public_keys" => Self::GetPublicKeys,
            "register_pub_key" => Self::RegisterPubKey,
            "register_address" => Self::RegisterAddress,
            "sign_tx" => Self::SignTx,
            "sign_message" => Self::SignMessage,
            "calc_external_address" => Self::CalcExternalAddress,
            "get_extended_public_keys" => Self::GetExtendedPublicKeys,
            "sign_psbt" => Self::SignPsbt,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChainType {
    Bitcoin,
    Dogecoin,
    Litecoin,
    BitcoinCash,
    Ethereum,
    Cosmos,
    Filecoin,
    Polkadot,
    Kusama,
    Tron,
    Nervos,
    Tezos,
    Eos,
}

impl ChainType {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "BITCOIN" => Self::Bitcoin,
            "DOGECOIN" => Self::Dogecoin,
            "LITECOIN" => Self::Litecoin,
            "BITCOINCASH" => Self::BitcoinCash,
            "ETHEREUM" => Self::Ethereum,
            "COSMOS" => Self::Cosmos,
            "FILECOIN" => Self::Filecoin,
            "POLKADOT" => Self::Polkadot,
            "KUSAMA" => Self::Kusama,
            "TRON" => Self::Tron,
            "NERVOS" => Self::Nervos,
            "TEZOS" => Self::Tezos,
            "EOS" => Self::Eos,
            _ => return None,
        })
    }

    pub(crate) fn is_btc_family(self) -> bool {
        matches!(
            self,
            Self::Bitcoin | Self::Dogecoin | Self::Litecoin | Self::BitcoinCash
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SegWit {
    None,
    P2wpkh,
    Version0,
    Version1,
    Other,
}

impl SegWit {
    pub(crate) fn from_name(name: &str) -> Self {
        match name.to_ascii_uppercase().as_str() {
            "NONE" => Self::None,
            "P2WPKH" => Self::P2wpkh,
            "VERSION_0" => Self::Version0,
            "VERSION_1" => Self::Version1,
            _ => Self::Other,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::P2wpkh => "P2WPKH",
            Self::Version0 => "VERSION_0",
            Self::Version1 => "VERSION_1",
            Self::Other => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_parse_is_case_insensitive() {
        assert_eq!(Some(Method::GetAddress), Method::from_name("GET_ADDRESS"));
        assert_eq!(
            Some(Method::ConfigureTsm),
            Method::from_name("CONFIGURE_TSM")
        );
        assert_eq!(None, Method::from_name("missing_method"));
    }

    #[test]
    fn chain_type_parse_is_strict() {
        assert_eq!(Some(ChainType::Dogecoin), ChainType::from_name("DOGECOIN"));
        assert_eq!(None, ChainType::from_name("dogecoin"));
    }

    #[test]
    fn seg_wit_parse_preserves_unknown_compatibility() {
        assert_eq!(SegWit::P2wpkh, SegWit::from_name("p2wpkh"));
        assert_eq!(SegWit::Other, SegWit::from_name(""));
        assert_eq!("VERSION_1", SegWit::Version1.as_str());
    }
}
