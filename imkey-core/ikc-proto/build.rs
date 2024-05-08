use std::env;
extern crate prost_build;

fn main() {
    // tcx-api
    env::set_var("OUT_DIR", "../ikc/src");
    prost_build::compile_protos(&["src/api.proto"], &["src/"]).unwrap();

    // common
    env::set_var("OUT_DIR", "../ikc-common/src");
    prost_build::compile_protos(&["src/common.proto"], &["src/"]).unwrap();

    // tcx-eth
    env::set_var("OUT_DIR", "../ikc-wallet/coin-ethereum/src");
    prost_build::compile_protos(&["src/eth.proto"], &["src/"]).unwrap();

    // tcx-btc
    env::set_var("OUT_DIR", "../ikc-wallet/coin-bitcoin/src");
    prost_build::compile_protos(&["src/btc.proto"], &["src/"]).unwrap();

    // tcx-eos
    env::set_var("OUT_DIR", "../ikc-wallet/coin-eos/src");
    prost_build::compile_protos(&["src/eos.proto"], &["src/"]).unwrap();

    // tcx-cosmos
    env::set_var("OUT_DIR", "../ikc-wallet/coin-cosmos/src");
    prost_build::compile_protos(&["src/cosmos.proto"], &["src/"]).unwrap();

    // device
    env::set_var("OUT_DIR", "../ikc-device/src");
    prost_build::compile_protos(&["src/device.proto"], &["src/"]).unwrap();

    // tcx-filecoin
    env::set_var("OUT_DIR", "../ikc-wallet/coin-filecoin/src");
    prost_build::compile_protos(&["src/filecoin.proto"], &["src/"]).unwrap();

    // ckb
    env::set_var("OUT_DIR", "../ikc-wallet/coin-ckb/src");
    prost_build::compile_protos(&["src/ckb.proto"], &["src/"]).unwrap();
    // subtrate
    env::set_var("OUT_DIR", "../ikc-wallet/coin-substrate/src");
    prost_build::compile_protos(&["src/substrate.proto"], &["src/"]).unwrap();

    // tron
    env::set_var("OUT_DIR", "../ikc-wallet/coin-tron/src");
    prost_build::compile_protos(&["src/tron.proto"], &["src/"]).unwrap();

    // tcx-tezos
    env::set_var("OUT_DIR", "../ikc-wallet/coin-tezos/src");
    prost_build::compile_protos(&["src/tezos.proto"], &["src/"]).unwrap();
    // tcx-btc-fork
    env::set_var("OUT_DIR", "../ikc-wallet/coin-btc-fork/src");
    prost_build::compile_protos(&["src/btcfork.proto"], &["src/"]).unwrap();
}

#[cfg(test)]
mod tests {
    use crate::main;
    use std::env;

    extern crate prost_build;

    #[test]
    fn it_works() {
        //run this test for propto build
    }
}
