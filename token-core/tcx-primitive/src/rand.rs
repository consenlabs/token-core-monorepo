use bip39::{Language, Mnemonic, MnemonicType};

pub fn generate_mnemonic() -> String {
    Mnemonic::new(MnemonicType::Words12, Language::English).to_string()
}

pub fn mnemonic_from_entropy(entropy: &[u8]) -> anyhow::Result<String> {
    let mn =
        Mnemonic::from_entropy(entropy, Language::English).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(mn.to_string())
}
