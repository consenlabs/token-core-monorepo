pub mod btc_fork_network;
pub mod coin_info;
pub mod curve;
pub mod sample_key;

pub use btc_fork_network::{
    coin_from_xpub_prefix, network_form_hrp, network_from_coin, pub_version_from_prv_version,
    BtcForkNetwork,
};
pub use coin_info::{coin_info_from_param, CoinInfo};
pub use curve::CurveType;

pub type Result<T> = std::result::Result<T, failure::Error>;

#[macro_use]
extern crate lazy_static;

pub const TEST_MNEMONIC: &'static str =
    "inject kidney empty canal shadow pact comfort wife crush horse wife sketch";
pub const TEST_PASSWORD: &'static str = "Insecure Pa55w0rd";

pub const TEST_WIF: &'static str = "cT4fTJyLd5RmSZFHnkGmVCzXDKuJLbyTt7cy77ghTTCagzNdPH1j";
pub const TEST_PRIVATE_KEY: &'static str =
    "0xcce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2";
