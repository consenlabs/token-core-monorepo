//! Test-only in-process APDU mock, copied only into an isolated temporary crate.
use crate::Result;
use anyhow::anyhow;
use parking_lot::Mutex;

type Handler = Box<dyn FnMut(&str, i32) -> Result<String> + Send>;
lazy_static! {
    static ref HANDLER: Mutex<Option<Handler>> = Mutex::new(None);
}

pub fn install(handler: Handler) {
    *HANDLER.lock() = Some(handler);
}

pub fn clear() {
    *HANDLER.lock() = None;
}

pub(crate) fn send(apdu: &str, timeout: i32) -> Result<String> {
    match HANDLER.lock().as_mut() {
        Some(handler) => handler(apdu, timeout),
        None => Err(anyhow!("offline APDU mock is not installed")),
    }
}
