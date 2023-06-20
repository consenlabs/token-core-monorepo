pub mod utility;
use std::result;

#[macro_use]
extern crate failure;
pub type Result<T> = result::Result<T, failure::Error>;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
