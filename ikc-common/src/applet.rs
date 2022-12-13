use crate::constants::{
    BCH_AID, BTC_AID, COSMOS_AID, EOS_AID, ETH_AID, FILECOIN_AID, IMK_AID, KUSAMA_AID, LTC_AID,
    NERVOS_AID, POLKADOT_AID, TEZOS_AID, TRON_AID,
};
// type __appletName = 'IMK' | 'Ethereum' | 'Bitcoin' | 'EOS' | 'Cosmos' | 'Filecoin' | 'Kusama' | 'Tezos' | 'Polkadot' | 'TRON' | 'Bitcoin Cash' | 'Litecoin' | 'Nervos'
pub fn get_appname_by_instid(instid: &str) -> Option<&str> {
    match instid {
        BTC_AID => Some("Bitcoin"),
        ETH_AID => Some("Ethereum"),
        EOS_AID => Some("EOS"),
        COSMOS_AID => Some("Cosmos"),
        FILECOIN_AID => Some("Filecoin"),
        KUSAMA_AID => Some("Kusama"),
        POLKADOT_AID => Some("Polkadot"),
        TRON_AID => Some("TRON"),
        BCH_AID => Some("Bitcoin Cash"),
        LTC_AID => Some("Litecoin"),
        IMK_AID => Some("IMK"),
        NERVOS_AID => Some("Nervos"),
        TEZOS_AID => Some("Tezos"),
        _ => None,
    }
}
pub fn get_instid_by_appname(appname: &str) -> Option<&str> {
    match appname {
        "Nervos" => Some(NERVOS_AID),
        "Tezos" => Some(TEZOS_AID),
        "Bitcoin" => Some(BTC_AID),
        "Ethereum" => Some(ETH_AID),
        "EOS" => Some(EOS_AID),
        "Cosmos" => Some(COSMOS_AID),
        "Filecoin" => Some(FILECOIN_AID),
        "Kusama" => Some(KUSAMA_AID),
        "Polkadot" => Some(POLKADOT_AID),
        "TRON" => Some(TRON_AID),
        "Bitcoin Cash" => Some(BCH_AID),
        "Litecoin" => Some(LTC_AID),
        "IMK" => Some(IMK_AID),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::applet::{get_appname_by_instid, get_instid_by_appname};
    #[test]
    fn get_appname_by_instid_test() {
        assert_eq!(get_appname_by_instid("695F627463").unwrap(), "Bitcoin");
        assert_eq!(get_appname_by_instid("695F657468").unwrap(), "Ethereum");
        assert_eq!(get_appname_by_instid("695F656F73").unwrap(), "EOS");
        assert_eq!(get_appname_by_instid("695F636F736D6F73").unwrap(), "Cosmos");
        assert_eq!(
            get_appname_by_instid("695F6B315F66696C").unwrap(),
            "FILECOIN"
        );
        assert_eq!(get_appname_by_instid("695F626368").unwrap(), "Bitcoin");
        assert_eq!(get_appname_by_instid("695F6C7463").unwrap(), "Litecoin");
        assert_eq!(get_appname_by_instid("695F696D6B").unwrap(), "IMK");
        assert!(get_appname_by_instid("1111111111").is_none());
    }

    #[test]
    fn get_instid_by_appname_test() {
        assert_eq!(get_instid_by_appname("Bitcoin").unwrap(), "695F627463");
        assert_eq!(get_instid_by_appname("Ethereum").unwrap(), "695F657468");
        assert_eq!(get_instid_by_appname("EOS").unwrap(), "695F656F73");
        assert_eq!(get_instid_by_appname("Cosmos").unwrap(), "695F636F736D6F73");
        assert_eq!(get_instid_by_appname("IMK").unwrap(), "695F696D6B");
        assert_eq!(
            get_instid_by_appname("Filecoin").unwrap(),
            "695F6B315F66696C"
        );
        assert_eq!(get_instid_by_appname("Bitcoin Cash").unwrap(), "695F626368");
        assert_eq!(get_instid_by_appname("Litecoin").unwrap(), "695F6C7463");
        assert!(get_instid_by_appname("APPLET").is_none());
    }
}
