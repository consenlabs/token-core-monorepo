use anyhow::{anyhow, Error};
use core::result;
use std::{cell::RefCell, panic};

pub type Result<T> = result::Result<T, Error>;

thread_local! {
    pub static LAST_ERROR: RefCell<Option<Error>> = RefCell::new(None);
}

#[allow(irrefutable_let_patterns)]
fn notify_err(err: Error) -> Error {
    let display_err = anyhow!("{}", &err);
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err);
    });
    display_err
}

/// catch any error and format to string
/// ref: <https://doc.rust-lang.org/edition-guide/rust-2018/error-handling-and-panics/controlling-panics-with-std-panic.html>
pub unsafe fn landingpad<F: FnOnce() -> Result<T> + panic::UnwindSafe, T>(f: F) -> Result<T> {
    match panic::catch_unwind(f) {
        Ok(rv) => rv.map_err(notify_err),
        Err(err) => {
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
