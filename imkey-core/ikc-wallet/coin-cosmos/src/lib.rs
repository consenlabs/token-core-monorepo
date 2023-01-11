pub mod address;
pub mod cosmosapi;
pub mod transaction;

#[macro_use]
extern crate failure;
use core::result;
pub type Result<T> = result::Result<T, failure::Error>;

// #[macro_use]
// extern crate serde_json;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
