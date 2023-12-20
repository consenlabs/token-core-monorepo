pub mod address;
// pub mod chain_factory;
pub mod signer;
pub mod transaction;
use bitcoin::util::base58;
// use base58::ToBase58;
use tcx_common::Result;
// pub use chain_factory::EosChainFactory;

pub mod eos {

    pub const CHAINS: [&'static str; 1] = ["EOS"];

    pub type Address = crate::address::EosAddress;
    pub type TransactionInput = crate::transaction::EosTxInput;
    pub type TransactionOutput = crate::transaction::EosTxOutput;

    pub type MessageInput = crate::transaction::EosMessageInput;

    pub type MessageOutput = crate::transaction::EosMessageOutput;
}

pub fn encode_eos_wif(private_key_bytes: &[u8]) -> Result<String> {
    let mut ret = [0; 33];
    ret[0..1].copy_from_slice(&vec![0x80]);
    ret[1..33].copy_from_slice(&private_key_bytes[..]);

    Ok(base58::check_encode_slice(&ret[..]))
}
