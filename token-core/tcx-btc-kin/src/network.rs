#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BtcKinNetwork {
    pub coin: String,
    pub network: String,

    pub bech32_hrp: String,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub private_prefix: u8,

    pub xpub_prefix: [u8; 4],
    pub xprv_prefix: [u8; 4],
}

lazy_static! {
    static ref BTC_KIN_NETWORKS: Vec<BtcKinNetwork> = {
        vec![
            BtcKinNetwork::new(
                "BITCOIN",
                "MAINNET",
                "bc",
                0x0,
                0x05,
                0x80,
                [0x04, 0x88, 0xb2, 0x1e],
                [0x04, 0x88, 0xad, 0xe4],
            ),
            BtcKinNetwork::new(
                "BITCOIN",
                "TESTNET",
                "tb",
                0x6f,
                0xc4,
                0xef,
                [0x04, 0x35, 0x87, 0xcf],
                [0x04, 0x35, 0x83, 0x94],
            ),
            BtcKinNetwork::new(
                "LITECOIN",
                "MAINNET",
                "ltc",
                0x30,
                0x32,
                0xb0,
                [0x04, 0x88, 0xb2, 0x1e],
                [0x04, 0x88, 0xad, 0xe4],
            ),
            BtcKinNetwork::new(
                "LITECOIN",
                "TESTNET",
                "tltc",
                0x6f,
                0x3a,
                0xef,
                [0x04, 0x35, 0x87, 0xcf],
                [0x04, 0x35, 0x83, 0x94],
            ),
            BtcKinNetwork::new(
                "BITCOINCASH",
                "MAINNET",
                "bitcoincash",
                0x0,
                0x05,
                0x80,
                [0x04, 0x88, 0xb2, 0x1e],
                [0x04, 0x88, 0xad, 0xe4],
            ),
            BtcKinNetwork::new(
                "BITCOINCASH",
                "TESTNET",
                "bchtest",
                0x6f,
                0xc4,
                0xef,
                [0x04, 0x35, 0x87, 0xcf],
                [0x04, 0x35, 0x83, 0x94],
            ),
        ]
    };
}

impl BtcKinNetwork {
    pub fn new(
        coin: &str,
        network: &str,
        hrp: &str,
        p2pkh: u8,
        p2sh: u8,
        private: u8,
        xpub: [u8; 4],
        xprv: [u8; 4],
    ) -> BtcKinNetwork {
        BtcKinNetwork {
            coin: coin.to_string(),
            network: network.to_string(),
            bech32_hrp: hrp.to_string(),
            p2pkh_prefix: p2pkh,
            p2sh_prefix: p2sh,
            private_prefix: private,
            xpub_prefix: xpub,
            xprv_prefix: xprv,
        }
    }

    pub fn find_by_coin<'a>(coin: &str, network: &str) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS
            .iter()
            .filter(|net| net.coin == coin && net.network == network)
            .next()
    }

    pub fn find_by_hrp<'a>(hrp: &str) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS
            .iter()
            .filter(|net| net.bech32_hrp == hrp)
            .next()
    }

    pub fn find_by_prefix<'a>(prefix: u8) -> Option<&'a BtcKinNetwork> {
        BTC_KIN_NETWORKS
            .iter()
            .filter(|net| net.p2pkh_prefix == prefix || net.p2sh_prefix == prefix)
            .next()
    }
}
