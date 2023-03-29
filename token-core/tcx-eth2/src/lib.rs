extern crate core;

pub mod address;
mod bls_to_execution_change;
pub mod signer;
pub mod transaction;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
