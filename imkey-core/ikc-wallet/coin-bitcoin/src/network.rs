#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtcKinNetwork {
    pub coin: &'static str,
    pub network: &'static str,

    pub bech32_hrp: &'static str,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub private_prefix: u8,

    pub xpub_prefix: [u8; 4],
    pub xprv_prefix: [u8; 4],
}
const BTC_KIN_NETWORKS: [BtcKinNetwork; 8] = [
    BtcKinNetwork {
        coin: "BITCOIN",
        network: "MAINNET",
        bech32_hrp: "bc",
        p2pkh_prefix: 0x0,
        p2sh_prefix: 0x05,
        private_prefix: 0x80,
        xpub_prefix: [0x04, 0x88, 0xb2, 0x1e],
        xprv_prefix: [0x04, 0x88, 0xad, 0xe4],
    },
    BtcKinNetwork {
        coin: "BITCOIN",
        network: "TESTNET",
        bech32_hrp: "tb",
        p2pkh_prefix: 0x6f,
        p2sh_prefix: 0xc4,
        private_prefix: 0xef,
        xpub_prefix: [0x04, 0x35, 0x87, 0xcf],
        xprv_prefix: [0x04, 0x35, 0x83, 0x94],
    },
    BtcKinNetwork {
        coin: "LITECOIN",
        network: "MAINNET",
        bech32_hrp: "ltc",
        p2pkh_prefix: 0x30,
        p2sh_prefix: 0x32,
        private_prefix: 0xb0,
        xpub_prefix: [0x04, 0x88, 0xb2, 0x1e],
        xprv_prefix: [0x04, 0x88, 0xad, 0xe4],
    },
    BtcKinNetwork {
        coin: "LITECOIN",
        network: "TESTNET",
        bech32_hrp: "tltc",
        p2pkh_prefix: 0x6f,
        p2sh_prefix: 0x3a,
        private_prefix: 0xef,
        xpub_prefix: [0x04, 0x35, 0x87, 0xcf],
        xprv_prefix: [0x04, 0x35, 0x83, 0x94],
    },
    BtcKinNetwork {
        coin: "BITCOINCASH",
        network: "MAINNET",
        bech32_hrp: "bitcoincash",
        p2pkh_prefix: 0x0,
        p2sh_prefix: 0x05,
        private_prefix: 0x80,
        xpub_prefix: [0x04, 0x88, 0xb2, 0x1e],
        xprv_prefix: [0x04, 0x88, 0xad, 0xe4],
    },
    BtcKinNetwork {
        coin: "BITCOINCASH",
        network: "TESTNET",
        bech32_hrp: "bchtest",
        p2pkh_prefix: 0x6f,
        p2sh_prefix: 0xc4,
        private_prefix: 0xef,
        xpub_prefix: [0x04, 0x35, 0x87, 0xcf],
        xprv_prefix: [0x04, 0x35, 0x83, 0x94],
    },
    BtcKinNetwork {
        coin: "DOGECOIN",
        network: "TESTNET",
        bech32_hrp: "",
        p2pkh_prefix: 0x71,
        p2sh_prefix: 0xc4,
        private_prefix: 0xf1,
        xpub_prefix: [0x04, 0x35, 0x87, 0xcf],
        xprv_prefix: [0x04, 0x35, 0x83, 0x94],
    },
    BtcKinNetwork {
        coin: "DOGECOIN",
        network: "MAINNET",
        bech32_hrp: "",
        p2pkh_prefix: 0x1e,
        p2sh_prefix: 0x16,
        private_prefix: 0x9e,
        xpub_prefix: [0x02, 0xfa, 0xca, 0xfd],
        xprv_prefix: [0x02, 0xfa, 0xc3, 0x98],
    },
];

impl BtcKinNetwork {
    pub fn find_by_coin<'a>(coin: &str, network: &str) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS
            .iter()
            .find(|net| net.coin == coin && net.network == network)
    }

    pub fn find_by_hrp<'a>(hrp: &str) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS.iter().find(|net| net.bech32_hrp == hrp)
    }

    pub fn find_by_prefix<'a>(prefix: u8) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS
            .iter()
            .find(|net| net.p2pkh_prefix == prefix || net.p2sh_prefix == prefix)
    }
}
