#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDownloadReq {
    #[prost(string, tag = "1")]
    pub app_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDownloadRes {
    #[prost(string, repeated, tag = "1")]
    pub address_register_list: ::std::vec::Vec<std::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppUpdateReq {
    #[prost(string, tag = "1")]
    pub app_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppUpdateRes {
    #[prost(string, repeated, tag = "1")]
    pub address_register_list: ::std::vec::Vec<std::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDeleteReq {
    #[prost(string, tag = "1")]
    pub app_name: std::string::String,
}
/// check_update api
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckUpdateRes {
    #[prost(string, tag = "1")]
    pub se_id: std::string::String,
    #[prost(string, tag = "2")]
    pub sn: std::string::String,
    #[prost(string, tag = "3")]
    pub status: std::string::String,
    #[prost(string, tag = "4")]
    pub sdk_mode: std::string::String,
    #[prost(message, repeated, tag = "5")]
    pub available_app_list: ::std::vec::Vec<AvailableAppBean>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AvailableAppBean {
    #[prost(string, tag = "1")]
    pub app_name: std::string::String,
    #[prost(string, tag = "2")]
    pub app_logo: std::string::String,
    #[prost(string, tag = "3")]
    pub installed_version: std::string::String,
    #[prost(string, tag = "4")]
    pub last_updated: std::string::String,
    #[prost(string, tag = "5")]
    pub latest_version: std::string::String,
    #[prost(string, tag = "6")]
    pub install_mode: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindCheckRes {
    #[prost(string, tag = "1")]
    pub bind_status: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindAcquireReq {
    #[prost(string, tag = "1")]
    pub bind_code: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindAcquireRes {
    #[prost(string, tag = "1")]
    pub bind_result: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSeidRes {
    #[prost(string, tag = "1")]
    pub seid: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnRes {
    #[prost(string, tag = "1")]
    pub sn: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRamSizeRes {
    #[prost(string, tag = "1")]
    pub ram_size: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetFirmwareVersionRes {
    #[prost(string, tag = "1")]
    pub firmware_version: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBatteryPowerRes {
    #[prost(string, tag = "1")]
    pub battery_power: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLifeTimeRes {
    #[prost(string, tag = "1")]
    pub life_time: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBleNameRes {
    #[prost(string, tag = "1")]
    pub ble_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetBleNameReq {
    #[prost(string, tag = "1")]
    pub ble_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBleVersionRes {
    #[prost(string, tag = "1")]
    pub ble_version: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSdkInfoRes {
    #[prost(string, tag = "1")]
    pub sdk_version: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceConnectReq {
    #[prost(string, tag = "1")]
    pub device_model_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CosCheckUpdateRes {
    #[prost(string, tag = "1")]
    pub seid: std::string::String,
    #[prost(bool, tag = "2")]
    pub is_latest: bool,
    #[prost(string, tag = "3")]
    pub latest_cos_version: std::string::String,
    #[prost(string, tag = "4")]
    pub update_type: std::string::String,
    #[prost(string, tag = "5")]
    pub description: std::string::String,
    #[prost(bool, tag = "6")]
    pub is_update_success: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsBlStatusRes {
    #[prost(bool, tag = "1")]
    pub check_result: bool,
}
