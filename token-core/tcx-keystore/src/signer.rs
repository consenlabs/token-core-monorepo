use crate::{Keystore, Result};

pub trait TransactionSigner<Input, Output> {
    fn sign_transaction(&mut self, symbol: &str, address: &str, tx: &Input) -> Result<Output>;
}

//pub trait Message: Sized {}
//pub trait SignedMessage: Sized {}
pub trait MessageSigner<Input, Output> {
    fn sign_message(&mut self, symbol: &str, address: &str, message: &Input) -> Result<Output>;
}

// The ec_sign
pub trait HashSigner {
    fn sign(&self, ks: &mut Keystore, symbol: &str, address: &str, hash: &[u8]) -> Result<Vec<u8>>;
}

pub trait ChainSigner {
    fn sign_recoverable_hash(
        &mut self,
        data: &[u8],
        symbol: &str,
        address: &str,
        path: Option<&str>,
    ) -> Result<Vec<u8>>;

    fn sign_hash(
        &mut self,
        data: &[u8],
        symbol: &str,
        address: &str,
        path: Option<&str>,
    ) -> Result<Vec<u8>>;

    fn sign_specified_hash(
        &mut self,
        data: &[u8],
        symbol: &str,
        address: &str,
        path: Option<&str>,
        dst: &str,
    ) -> Result<Vec<u8>>;
}
