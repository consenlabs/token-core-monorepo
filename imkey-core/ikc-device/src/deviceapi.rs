#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDownloadReq {
    #[prost(string, tag = "1")]
    pub app_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDownloadRes {
    #[prost(string, repeated, tag = "1")]
    pub address_register_list: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppUpdateReq {
    #[prost(string, tag = "1")]
    pub app_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppUpdateRes {
    #[prost(string, repeated, tag = "1")]
    pub address_register_list: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDeleteReq {
    #[prost(string, tag = "1")]
    pub app_name: ::prost::alloc::string::String,
}
/// check_update api
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckUpdateRes {
    #[prost(string, tag = "1")]
    pub se_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub sn: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub status: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub sdk_mode: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "5")]
    pub available_app_list: ::prost::alloc::vec::Vec<AvailableAppBean>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AvailableAppBean {
    #[prost(string, tag = "1")]
    pub app_name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub app_logo: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub installed_version: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub last_updated: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub latest_version: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub install_mode: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindCheckRes {
    #[prost(string, tag = "1")]
    pub bind_status: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindAcquireReq {
    #[prost(string, tag = "1")]
    pub bind_code: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub bind_status: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindAcquireRes {
    #[prost(string, tag = "1")]
    pub bind_result: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSeidRes {
    #[prost(string, tag = "1")]
    pub seid: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnRes {
    #[prost(string, tag = "1")]
    pub sn: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRamSizeRes {
    #[prost(string, tag = "1")]
    pub ram_size: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetFirmwareVersionRes {
    #[prost(string, tag = "1")]
    pub firmware_version: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBatteryPowerRes {
    #[prost(string, tag = "1")]
    pub battery_power: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLifeTimeRes {
    #[prost(string, tag = "1")]
    pub life_time: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBleNameRes {
    #[prost(string, tag = "1")]
    pub ble_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetBleNameReq {
    #[prost(string, tag = "1")]
    pub ble_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBleVersionRes {
    #[prost(string, tag = "1")]
    pub ble_version: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSdkInfoRes {
    #[prost(string, tag = "1")]
    pub sdk_version: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceConnectReq {
    #[prost(string, tag = "1")]
    pub device_model_name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosCheckUpdateRes {
    #[prost(string, tag = "1")]
    pub seid: ::prost::alloc::string::String,
    #[prost(bool, tag = "2")]
    pub is_latest: bool,
    #[prost(string, tag = "3")]
    pub latest_cos_version: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub update_type: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub description: ::prost::alloc::string::String,
    #[prost(bool, tag = "6")]
    pub is_update_success: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsBlStatusRes {
    #[prost(bool, tag = "1")]
    pub check_result: bool,
}
