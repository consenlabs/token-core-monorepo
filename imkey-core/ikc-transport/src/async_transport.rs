#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
))]
use crate::message::ApduTransport;
use crate::Result;
use std::future::Future;
use std::pin::Pin;

pub type BoxFutureResult<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProfile {
    WebUsb,
    WebHid,
    Ble,
    NativeHid,
}

pub trait AsyncApduTransport {
    fn profile(&self) -> TransportProfile;
    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String>;
}

pub trait AsyncReconnectableTransport: AsyncApduTransport {
    fn reconnect<'a>(&'a self, timeout: i32) -> BoxFutureResult<'a, ()>;
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub struct AsyncHidApduTransport;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl AsyncApduTransport for AsyncHidApduTransport {
    fn profile(&self) -> TransportProfile {
        TransportProfile::NativeHid
    }

    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String> {
        Box::pin(async move { crate::message::HidApduTransport.send_apdu_timeout(apdu, timeout) })
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl AsyncReconnectableTransport for AsyncHidApduTransport {
    fn reconnect<'a>(&'a self, timeout: i32) -> BoxFutureResult<'a, ()> {
        Box::pin(async move {
            let attempts = timeout.max(1);
            for _ in 0..attempts {
                if crate::hid_api::hid_connect("imKey Pro").is_ok() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(anyhow::anyhow!("imkey_transport_reconnect_timeout"))
        })
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub struct AsyncCallbackApduTransport;

#[cfg(any(target_os = "android", target_os = "ios"))]
impl AsyncApduTransport for AsyncCallbackApduTransport {
    fn profile(&self) -> TransportProfile {
        TransportProfile::Ble
    }

    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String> {
        Box::pin(
            async move { crate::message::CallbackApduTransport.send_apdu_timeout(apdu, timeout) },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAsyncTransport;

    impl AsyncApduTransport for MockAsyncTransport {
        fn profile(&self) -> TransportProfile {
            TransportProfile::WebUsb
        }

        fn send_apdu<'a>(&'a self, apdu: &'a str, _timeout: i32) -> BoxFutureResult<'a, String> {
            Box::pin(async move { Ok(format!("{apdu}9000")) })
        }
    }

    impl AsyncReconnectableTransport for MockAsyncTransport {
        fn reconnect<'a>(&'a self, _timeout: i32) -> BoxFutureResult<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn async_transport_trait_is_platform_independent() {
        let transport = MockAsyncTransport;
        assert_eq!(transport.profile(), TransportProfile::WebUsb);
        let response = futures_lite::future::block_on(transport.send_apdu("00A4", 20)).unwrap();
        assert_eq!(response, "00A49000");
        futures_lite::future::block_on(transport.reconnect(1)).unwrap();
    }
}
