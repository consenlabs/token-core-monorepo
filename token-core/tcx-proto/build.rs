use std::env;
extern crate prost_build;

fn main() {
    // tcx-api
    env::set_var("OUT_DIR", "../tcx/src");
    prost_build::compile_protos(
        &[
            "src/api.proto",
            "src/params.proto",
            "src/cache_derived_key.proto",
        ],
        &["src/"],
    )
    .unwrap();

    //    // tcx-chain
    //    env::set_var("OUT_DIR", "../tcx-chain/src");
    //    prost_build::compile_protos(&["src/tron.proto"], &["src/"]).unwrap();

    // tcx-atom
    env::set_var("OUT_DIR", "../tcx-atom/src");
    prost_build::compile_protos(&["src/atom.proto"], &["src/"]).unwrap();

    // tcx-eos
    env::set_var("OUT_DIR", "../tcx-eos/src");
    prost_build::compile_protos(&["src/eos.proto"], &["src/"]).unwrap();

    // tcx-tron
    env::set_var("OUT_DIR", "../tcx-tron/src");
    prost_build::compile_protos(&["src/tron.proto"], &["src/"]).unwrap();

    // tcx-btc-fork
    env::set_var("OUT_DIR", "../tcx-btc-kin/src");
    prost_build::compile_protos(&["src/btc_kin.proto"], &["src/"]).unwrap();

    // tcx-ckb
    env::set_var("OUT_DIR", "../tcx-ckb/src");
    prost_build::compile_protos(&["src/ckb.proto"], &["src/"]).unwrap();

    // tcx-substrate
    env::set_var("OUT_DIR", "../tcx-substrate/src");
    prost_build::compile_protos(&["src/substrate.proto"], &["src/"]).unwrap();

    env::set_var("OUT_DIR", "../tcx-filecoin/src");
    prost_build::compile_protos(&["src/filecoin.proto"], &["src/"]).unwrap();

    //    let targets = vec!["arm64-v8a", "armeabi-v7a", "x86", "x86_64"];
    //    for target in targets {
    //        println!("cargo:rustc-link-search=../../android/tokencore/build/intermediates/cmake/release/obj/{}/", target);
    //    }

    //tcx-tezos
    env::set_var("OUT_DIR", "../tcx-tezos/src");
    prost_build::compile_protos(&["src/tezos.proto"], &["src/"]).unwrap();

    //tcx-eth2
    env::set_var("OUT_DIR", "../tcx-eth2/src");
    prost_build::compile_protos(&["src/eth2.proto"], &["src/"]).unwrap();

    //tcx-wallet
    env::set_var("OUT_DIR", "../tcx-wallet/src");
    prost_build::compile_protos(&["src/wallet_api.proto"], &["src/"]).unwrap();

    //tcx-eth
    env::set_var("OUT_DIR", "../tcx-eth/src");
    prost_build::compile_protos(&["src/eth.proto"], &["src/"]).unwrap();
}
