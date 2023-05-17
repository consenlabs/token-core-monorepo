// use bip39::{Language, Mnemonic, MnemonicType};
//
// fn create_identity(name: &str, password: &str, password_hit: &str, network: &str, seg_wit: Option<&str>){
//     //生成助记词
//     let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
//     let phrase = mnemonic.phrase();
//     println!("{}", phrase);
//
// }
//
// struct Metadata{
//
// }

#[cfg(test)]
mod test {
    use crate::identity::create_identity;

    #[test]
    fn test_create_identity() {
        create_identity("name", "123456", "password_hit", "mainnet", None);
    }
}
