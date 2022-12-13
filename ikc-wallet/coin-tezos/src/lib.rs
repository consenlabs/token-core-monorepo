pub mod address;
pub mod tezosapi;
pub mod transaction;
use core::result;
#[macro_use]
extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
