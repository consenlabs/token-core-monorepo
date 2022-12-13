use core::result;

pub mod address;
pub mod btc_fork_network;
pub mod btcforkapi;
pub mod common;
pub mod transaction;

pub type Result<T> = result::Result<T, failure::Error>;
extern crate failure;

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
