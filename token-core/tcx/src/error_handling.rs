use crate::filemanager::KEYSTORE_MAP;
use anyhow::{anyhow, Error};
use core::result;
use std::{cell::RefCell, panic};
pub type Result<T> = result::Result<T, Error>;

thread_local! {
    pub static LAST_ERROR: RefCell<Option<Error>> = RefCell::new(None);
}

#[cfg_attr(tarpaulin, ignore)]
#[allow(irrefutable_let_patterns)]
fn notify_err(err: Error) -> Error {
    let display_err = anyhow!("{}", &err);
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err);
    });
    display_err
}

fn lock_all_keystore() {
    let mut map = KEYSTORE_MAP.write();
    for ks in map.values_mut() {
        ks.lock();
    }
}

/// catch any error and format to string
/// ref: <https://doc.rust-lang.org/edition-guide/rust-2018/error-handling-and-panics/controlling-panics-with-std-panic.html>
/// # Safety
///
#[cfg_attr(tarpaulin, ignore)]
pub unsafe fn landingpad<F: FnOnce() -> Result<T> + panic::UnwindSafe, T>(f: F) -> Result<T> {
    match panic::catch_unwind(f) {
        Ok(rv) => {
            lock_all_keystore();
            rv.map_err(notify_err)
        }
        Err(err) => {
            lock_all_keystore();
            use std::any::Any;
            let err = &*err as &dyn Any;
            let msg = match err.downcast_ref::<&str>() {
                Some(s) => *s,
                None => match err.downcast_ref::<String>() {
                    Some(s) => &**s,
                    None => "Box<Any>",
                },
            };
            Err(notify_err(anyhow!("{}", msg)))
        }
    }
}
