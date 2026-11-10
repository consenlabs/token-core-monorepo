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

// Keep the synchronous native protocol off the executor thread. Dropping the
// future does not cancel an in-flight device command; its worker finishes it.
#[cfg(not(target_arch = "wasm32"))]
async fn native_worker<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = futures_channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(operation());
    });
    receiver
        .await
        .map_err(|_| anyhow::anyhow!("imkey_transport_worker_failed"))?
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub struct AsyncHidApduTransport;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl AsyncApduTransport for AsyncHidApduTransport {
    fn profile(&self) -> TransportProfile {
        TransportProfile::NativeHid
    }

    fn send_apdu<'a>(&'a self, apdu: &'a str, timeout: i32) -> BoxFutureResult<'a, String> {
        let apdu = apdu.to_owned();
        Box::pin(native_worker(move || {
            crate::message::HidApduTransport.send_apdu_timeout(&apdu, timeout)
        }))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl AsyncReconnectableTransport for AsyncHidApduTransport {
    fn reconnect<'a>(&'a self, timeout: i32) -> BoxFutureResult<'a, ()> {
        Box::pin(native_worker(move || {
            let attempts = timeout.max(1);
            for _ in 0..attempts {
                if crate::hid_api::hid_connect("imKey Pro").is_ok() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(anyhow::anyhow!("imkey_transport_reconnect_timeout"))
        }))
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
        let apdu = apdu.to_owned();
        Box::pin(native_worker(move || {
            crate::message::CallbackApduTransport.send_apdu_timeout(&apdu, timeout)
        }))
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
    #[cfg(not(target_arch = "wasm32"))]
    fn native_worker_yields_and_recovers_after_failure() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let (release, wait) = std::sync::mpsc::channel();
        let mut operation = Box::pin(native_worker(move || {
            wait.recv().unwrap();
            Err::<(), _>(anyhow::anyhow!("mock_device_failure"))
        }));
        let waker = Waker::noop();
        assert!(matches!(
            operation.as_mut().poll(&mut Context::from_waker(waker)),
            Poll::Pending
        ));
        release.send(()).unwrap();
        assert_eq!(
            futures_lite::future::block_on(operation)
                .unwrap_err()
                .to_string(),
            "mock_device_failure"
        );
        assert_eq!(
            futures_lite::future::block_on(native_worker(|| Ok(42))).unwrap(),
            42
        );
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
