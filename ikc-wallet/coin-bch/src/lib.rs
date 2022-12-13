use core::result;

pub mod address;
mod common;
pub mod transaction;
pub type Result<T> = result::Result<T, failure::Error>;
extern crate failure;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
