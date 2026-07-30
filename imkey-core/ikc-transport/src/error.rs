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

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum TransportError {
    #[error("imkey_transport_permission_cancelled")]
    PermissionCancelled,
    #[error("imkey_transport_device_disconnected")]
    DeviceDisconnected,
    #[error("imkey_send_apdu_timeout")]
    Timeout,
    #[error("imkey_transport_illegal_response")]
    IllegalResponse,
}

pub fn map_transport_error_code(code: &str) -> TransportError {
    match code {
        "webusb_permission_cancelled" => TransportError::PermissionCancelled,
        "webusb_device_disconnected" => TransportError::DeviceDisconnected,
        "webusb_apdu_timeout" => TransportError::Timeout,
        _ => TransportError::IllegalResponse,
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{map_transport_error_code, TransportError};

    #[test]
    fn transport_errors_map_webusb_codes_to_stable_errors() {
        assert_eq!(
            map_transport_error_code("webusb_permission_cancelled"),
            TransportError::PermissionCancelled
        );
        assert_eq!(
            map_transport_error_code("webusb_device_disconnected"),
            TransportError::DeviceDisconnected
        );
        assert_eq!(
            map_transport_error_code("webusb_apdu_timeout"),
            TransportError::Timeout
        );
        assert_eq!(
            map_transport_error_code("unknown"),
            TransportError::IllegalResponse
        );
    }
}
