use thiserror::Error;

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum HidError {
    #[error("imkey_device_not_connect")]
    DeviceIsNotConnectOrNoVerifyPin,
    #[error("device_connect_interface_not_called")]
    DeviceConnectInterfaceNotCalled,
    #[error("device_data_read_time_out")]
    DeviceDataReadTimeOut,
}
