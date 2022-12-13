pub mod address;
pub mod filecoinapi;
pub mod transaction;
pub mod utils;
use core::result;
pub type Result<T> = result::Result<T, failure::Error>;
#[macro_use]
extern crate failure;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
