use lazy_static::lazy_static;

lazy_static! {
    /// Lazily initialized secp256k1 engine
    pub static ref SECP256K1_ENGINE: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();
}
