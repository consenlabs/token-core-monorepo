pub mod address;
pub mod signer;
pub mod transaction;
pub mod types;

use core::result;

pub type Result<T> = result::Result<T, failure::Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // let result = add(2, 2);
        // assert_eq!(result, 4);
    }
}
