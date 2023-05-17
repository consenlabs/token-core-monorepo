use crate::Result;
use core::result;
use tcx_primitive;

pub fn generate_Mnemonic() -> Result<String> {
    let mnemonic = tcx_primitive::generate_mnemonic();
    Ok(mnemonic)
}
