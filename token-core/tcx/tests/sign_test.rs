use common::run_test;
use serial_test::serial;
use tcx::api::{EthBatchPersonalSignParam, EthBatchPersonalSignResult};

mod common;
use api::sign_param::Key;

use tcx::api::derive_accounts_param::Derivation;
use tcx::api::sign_hashes_param::DataToSign;
use tcx::filemanager::KEYSTORE_MAP;

use tcx::*;
use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};

use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};

use crate::common::*;
use prost::Message;
use sp_core::ByteArray;
use sp_runtime::traits::Verify;

use tcx::api::{
    sign_param, DeriveAccountsParam, DeriveAccountsResult, DerivedKeyResult, GeneralResult,
    GetPublicKeysParam, GetPublicKeysResult, ImportMnemonicParam, KeystoreResult,
    PublicKeyDerivation, SignHashesParam, SignHashesResult, SignParam, WalletKeyParam,
};

use tcx::handler::encode_message;
use tcx::handler::get_derived_key;
use tcx_btc_kin::transaction::{BtcKinTxInput, BtcMessageInput, BtcMessageOutput};
use tcx_btc_kin::Utxo;
use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};
use tcx_constants::{sample_key, CurveType};
use tcx_constants::{OTHER_MNEMONIC, TEST_PASSWORD};
use tcx_keystore::Keystore;

use tcx_common::hex::FromHex;
use tcx_eth::transaction::{
    AccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
};
use tcx_filecoin::{SignedMessage, UnsignedMessage};
use tcx_substrate::{SubstrateRawTxIn, SubstrateTxOut};
use tcx_tezos::transaction::{TezosRawTxIn, TezosTxOut};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};

#[test]
#[serial]
pub fn test_sign_ckb_tx() {
    run_test(|| {
        let wallet: KeystoreResult = import_default_wallet();
        let out_points = vec![
            OutPoint {
                tx_hash: "0xfb9c020db967e84af1fbd755df5bc23427e2ed70f73e07895a0c394f6195f083"
                    .to_owned(),
                index: 0,
            },
            OutPoint {
                tx_hash: "0xfb9c020db967e84af1fbd755df5bc23427e2ed70f73e07895a0c394f6195f083"
                    .to_owned(),
                index: 1,
            },
        ];

        let code_hash =
            "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8".to_owned();

        let input = CkbTxInput {
            inputs: vec![
                CellInput {
                    previous_output: Some(out_points[0].clone()),
                    since: "".to_string(),
                },
                CellInput {
                    previous_output: Some(out_points[1].clone()),
                    since: "".to_string(),
                },
            ],
            witnesses: vec![Witness::default(), Witness::default()],
            cached_cells: vec![
                CachedCell {
                    capacity: 0,
                    lock: Some(Script {
                        hash_type: "type".to_string(),
                        code_hash: code_hash.clone(),
                        args: "0xb45772677603bccc71194b2557067fb361c1e093".to_owned(),
                    }),
                    out_point: Some(out_points[0].clone()),
                    derived_path: "m/44'/309'/0'/0/1".to_string(),
                },
                CachedCell {
                    capacity: 0,
                    lock: Some(Script {
                        hash_type: "type".to_string(),
                        code_hash: code_hash.clone(),
                        args: "0x2d79d9ed37184c1136bcfbe229947a137f80dec0".to_owned(),
                    }),
                    out_point: Some(out_points[1].clone()),
                    derived_path: "m/44'/309'/0'/1/0".to_string(),
                },
            ],
            tx_hash: "0x102b8e88daadf1b035577b4d5ea4f604be965df6a918e72daeff6c0c40753401"
                .to_owned(),
        };

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "NERVOS".to_string(),
            path: "m/44'/309'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1.as_str().to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(input).unwrap(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: CkbTxOutput = CkbTxOutput::decode(ret.as_slice()).unwrap();
        assert_eq!("0x5500000010000000550000005500000041000000776e010ac7e7166afa50fe54cfecf0a7106a2f11e8110e071ccab67cb30ed5495aa5c5f5ca2967a2fe4a60d5ad8c811382e51d8f916ba2911552bef6dedeca8a00", output.witnesses[0]);
        assert_eq!("0x5500000010000000550000005500000041000000914591d8abd5233740207337b0588fec58cad63143ddf204970526022b6db26d68311e9af49e1625e3a90e8a66eb1694632558d561d1e5d02cc7c7254e2d546100", output.witnesses[1]);

        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
pub fn test_sign_tron_tx() {
    run_test(|| {
        let wallet = import_default_wallet();

        let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
        let input = TronTxInput { raw_data };
        let input_value = encode_message(input).unwrap();
        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password("WRONG PASSWORD".to_string())),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            curve: "secp256k1".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TRON1".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
        let expected_sign = "bbf5ce0549490613a26c3ac4fc8574e748eabda05662b2e49cea818216b9da18691e78cd6379000e9c8a35c13dfbf620f269be90a078b58799b56dc20da3bdf200";
        assert_eq!(expected_sign, output.signatures[0]);
        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
pub fn test_sign_cosmos_tx() {
    run_test(|| {
        let wallet = import_default_wallet();

        let raw_data = "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201".to_string();
        let input = AtomTxInput { raw_data };
        let input_value = encode_message(input).unwrap();
        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password("WRONG PASSWORD".to_string())),
            chain_type: "COSMOS".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "COSMOS1".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "COSMOS".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: AtomTxOutput = AtomTxOutput::decode(ret.as_slice()).unwrap();
        let expected_sig = "355fWQ00dYitAZj6+EmnAgYEX1g7QtUrX/kQIqCbv05TCz0dfsWcMgXWVnr1l/I2hrjjQkiLRMoeRrmnqT2CZA==";
        assert_eq!(expected_sig, output.signature);
        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
pub fn test_sign_substrate_raw_tx() {
    run_test(|| {
        let wallet = import_default_wallet();

        let unsigned_msg = "0x0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7";
        let input = SubstrateRawTxIn {
            raw_data: unsigned_msg.to_string(),
        };

        let input_value = encode_message(input).unwrap();
        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "KUSAMA".to_string(),
            path: "//kusama//imToken/0".to_string(),
            curve: "sr25519".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: SubstrateTxOut = SubstrateTxOut::decode(ret.as_slice()).unwrap();

        assert_eq!(output.signature[0..4].to_string(), "0x01",);

        let sig_bytes = Vec::from_hex(output.signature[4..].to_string()).unwrap();
        let signature = sp_core::sr25519::Signature::from_slice(&sig_bytes).unwrap();

        let pub_key =
            Vec::from_hex("90742a577c8515391a46b7881c98c80ec92fe04255bb5b5fec862c7d633ada21")
                .unwrap();
        let singer = sp_core::sr25519::Public::from_slice(&pub_key).unwrap();
        let msg = Vec::from_hex("0600ffd7568e5f0a7eda67a82691ff379ac4bba4f9c9b859fe779b5d46363b61ad2db9e56c0703d148e25901007b000000dcd1346701ca8396496e52aa2785b1748deb6db09551b72159dcb3e08991025bde8f69eeb5e065e18c6950ff708d7e551f68dc9bf59a07c52367c0280f805ec7").unwrap();

        assert!(
            sp_core::sr25519::Signature::verify(&signature, msg.as_slice(), &singer),
            "assert sig"
        );

        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
pub fn test_sign_tron_tx_by_pk() {
    run_test(|| {
        let import_result = import_default_pk_store();

        let derivation = Derivation {
            chain_type: "TRON".to_string(),
            path: "".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "".to_string(),
        };
        let param = DeriveAccountsParam {
            id: import_result.id.to_string(),
            key: Some(crate::api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations: vec![derivation],
        };

        let ret = call_api("derive_accounts", param).unwrap();
        let _rsp: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

        let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
        let input = TronTxInput { raw_data };
        let tx = SignParam {
            id: import_result.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(input).unwrap(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
        let expected_sign = "7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001";
        assert_eq!(expected_sign, output.signatures[0]);
        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_sign_filecoin_bls() {
    run_test(|| {
        let import_result = import_filecoin_pk_store();

        let message = UnsignedMessage {
                to: "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
                from: "t3r52r4c7dxhzuhubdenjuxgfak5tbmb3pbcv35wngm6qgvo7bwmvbuuw274rwyhcp53ydtt3ugexjnltnk75q".to_string(),
                nonce: 0,
                value: "100000".to_string(),
                gas_limit: 10000,
                gas_fee_cap: "20000".to_string(),
                gas_premium: "20000".to_string(),
                method: 0,
                params: "".to_string()
            };

        let tx = SignParam {
            id: import_result.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "FILECOIN".to_string(),
            path: "m/44'/461'/0'/0/0".to_string(),
            curve: "bls12-381".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(message).unwrap(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let signed = SignedMessage::decode(ret.as_slice()).unwrap();
        let expected_sign = "r+CN2nhRN7d23jTFDvescYjkqg6iFwlcb2yZugewBsLko96E+UEYuSuhheaSGu1SDU7gYx54tsxYC/Zq3Pk0gfTAHPC2Ui9P5oNE3hNtb0mHO7D4ZHID2I4RxKFTAY8N" ;
        assert_eq!(expected_sign, signed.signature.unwrap().data);

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_sign_filecoin_secp256k1() {
    run_test(|| {
        let import_result = import_default_pk_store();

        let message = UnsignedMessage {
            to: "t12i3bop43tprlnymx2c75u6uvlq7iur2rcd7qsey".to_string(),
            from: "t1zerdvi3fx2lrcslsqdewpadzzm2hefpn6ixew3i".to_string(),
            nonce: 0,
            value: "100000".to_string(),
            gas_limit: 10000,
            gas_fee_cap: "20000".to_string(),
            gas_premium: "20000".to_string(),
            method: 0,
            params: "".to_string(),
        };

        let tx = SignParam {
            id: import_result.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "FILECOIN".to_string(),
            path: "m/44'/461'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(message).unwrap(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let signed = SignedMessage::decode(ret.as_slice()).unwrap();
        let expected_sign = "YJLfRrV7WovsWUY4nhKRp8Vs9AGC9J61zV8InwWM6IwxBVhtc20mJC7cxWdVMBQ45Mem2yS7bqQe7alkSxQvpwA=" ;
        assert_eq!(expected_sign, signed.signature.unwrap().data);

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_sign_by_dk_in_pk_store() {
    run_test(|| {
        let import_result = import_default_pk_store();

        let param = WalletKeyParam {
            id: import_result.id.to_string(),
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret_bytes = get_derived_key(&encode_message(param).unwrap()).unwrap();
        let ret: DerivedKeyResult = DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();
        let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
        let input = TronTxInput { raw_data };
        let tx = SignParam {
            id: import_result.id.to_string(),
            key: Some(Key::DerivedKey(ret.derived_key)),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(input.clone()).unwrap(),
            }),
        };

        let ret = call_api("sign_tx", tx).unwrap();
        let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
        let expected_sign = "7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001";
        assert_eq!(expected_sign, output.signatures[0]);

        let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::DerivedKey("7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input.clone()).unwrap(),
                }),
            };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!("password_incorrect", format!("{}", ret.err().unwrap()));

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
fn test_tron_sign_message() {
    run_test(|| {
        let wallet = import_default_wallet();

        let input_expects = vec![
                (TronMessageInput {
                    value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                    version: "V1".to_string(),
                }, "0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                        .to_string(),
                    is_tron_header: true,
                    version: "V1".to_string(),
                }, "0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b"),
                (TronMessageInput {
                    value: "abcdef"
                        .to_string(),
                    is_tron_header: true,
                    version: "V1".to_string(),
                }, "0x13e407627e584c821ba527d23d64163d458447dfea1c3bfc92be660aa8d093ee5cfa3881870c4c51f157828eb9d4f7fad8112761f3b51cf76c7a4a3f241033d51b"),
            ];
        for (input, expected) in input_expects {
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let sign_result = call_api("sign_msg", tx).unwrap();
            let ret: TronMessageOutput = TronMessageOutput::decode(sign_result.as_slice()).unwrap();
            assert_eq!(expected, ret.signature);
        }
    });
}

#[test]
#[serial]
fn test_tron_sign_message_v2() {
    run_test(|| {
        let wallet = import_default_wallet();

        let input = TronMessageInput {
            value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"
                .to_string(),
            is_tron_header: true,
            version: "V2".to_string(),
        };
        
        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(input).unwrap(),
            }),
        };

        let sign_result = call_api("sign_msg", tx).unwrap();
        let ret: TronMessageOutput = TronMessageOutput::decode(sign_result.as_slice()).unwrap();
        assert_eq!("0x9e7a691647c02fad5fe939a50df0351a58be67b3cdd87619c37f316b913d0be92ecf190f5e0c3640d54d9be731e8ab4bea4894ca9e7267b6c86d852e5c5dd71d1c", ret.signature);
        
    });
}

#[test]
#[serial]
fn test_bitcoin_sign_message() {
    run_test(|| {
        let wallet = import_default_wallet();

        let input_expects = vec![
            (BtcMessageInput{
                message: "hello world".to_string(),
            }, "02473044022062775640116afb7f17d23c222b0a6904fdaf2aea0d76e550d75c8fd362b80dcb022067c299fde774aaab689f8a53ebd0956395ff45b7ff6b7e99569d0abec85110c80121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"),
            (BtcMessageInput{
                message: "test1".to_string(),
            }, "02483045022100b805ccd16f1a664ae394bf292962ea6d76e0ddd5beb0b050cca4a1aa9ababc9a02201503132e39dc600957ec8f33663b10ab0cff0c4e37cab2811619152be8d919300121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"),
            (BtcMessageInput{
                message: "test2".to_string(),
            }, "02483045022100e96bfdb41b3562a1ff5a4c816da2620e82bcc8d702843ae1cec506666d4569c302206477d7d93c082cb42d462200a136e6aef7edde053722008a206ab8b9b356f0380121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"),
        ];

        for (input, expected) in input_expects {
            let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: "BITCOIN".to_string(),
                path: "m/49'/1'/0'".to_string(),
                curve: "secp256k1".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

            let sign_result = call_api("sign_msg", tx).unwrap();
            let ret: BtcMessageOutput = BtcMessageOutput::decode(sign_result.as_slice()).unwrap();
            assert_eq!(expected, ret.signature);
        }
    });
}

#[test]
#[serial]
fn test_sign_by_dk_hd_store() {
    run_test(|| {
        let wallet = import_default_wallet();
        let input = TronMessageInput {
            value: "0x645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76".to_string(),
            is_tron_header: true,
            version: "V1".to_string()
        };

        let dk_param = WalletKeyParam {
            id: wallet.id.to_string(),
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };

        let ret_bytes = get_derived_key(&encode_message(dk_param).unwrap()).unwrap();
        let ret: DerivedKeyResult = DerivedKeyResult::decode(ret_bytes.as_slice()).unwrap();

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::DerivedKey(ret.derived_key)),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: encode_message(input.clone()).unwrap(),
            }),
        };

        let sign_result = call_api("sign_msg", tx).unwrap();
        let ret: TronMessageOutput = TronMessageOutput::decode(sign_result.as_slice()).unwrap();
        assert_eq!("0x16417c6489da3a88ef980bf0a42551b9e76181d03e7334548ab3cb36e7622a484482722882a29e2fe4587b95c739a68624ebf9ada5f013a9340d883f03fcf9af1b", ret.signature);

        let tx = SignParam {
                id: wallet.id.to_string(),
                key: Some(Key::DerivedKey("7758c92df76d50774a67fdca6c90b922fc84be68c69164d4c7f500327bfa4b9655709b6b1f88e07e3bda266d7ca4b48c934557917692f63a31e301d79d7107d001".to_string())),
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: encode_message(input).unwrap(),
                }),
            };

        let ret = call_api("sign_msg", tx);
        assert!(ret.is_err());
        assert_eq!("password_incorrect", format!("{}", ret.err().unwrap()));

        remove_created_wallet(&wallet.id);
    });
}

#[test]
#[serial]
pub fn test_sign_btc_fork_invalid_address() {
    run_test(|| {
        let chain_types = vec!["BITCOIN", "LITECOIN", "BITCOINCASH"];

        let import_result: KeystoreResult = import_default_wallet();

        for chain_type in chain_types {
            let inputs = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                derived_path: "0/0".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                inputs,
                to: "invalid_address".to_string(),
                amount: 500000,
                fee: 100000,
                change_address_index: Some(1u32),
                op_return: None,
            };
            let input_value = encode_message(tx_input).unwrap();
            let tx = SignParam {
                id: import_result.id.to_string(),
                key: Some(Key::Password(TEST_PASSWORD.to_string())),
                chain_type: chain_type.to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                input: Some(::prost_types::Any {
                    type_url: "imtoken".to_string(),
                    value: input_value.clone(),
                }),
            };

            let ret = call_api("sign_tx", tx);
            assert!(ret.is_err());
            assert_eq!(format!("{}", ret.err().unwrap()), "invalid_address");
        }

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_lock_after_sign() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "".to_string(),
        };

        let (wallet, _acc_rsp) = import_and_derive(derivation);

        let raw_data = "0a0202a22208e216e254e43ee10840c8cbe4e3df2d5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15415c68cc82c87446f602f019e5fd797437f5b79cc212154156a6076cd1537fa317c2606e4edfa4acd3e8e92e18a08d06709084e1e3df2d".to_string();
        let input = TronTxInput { raw_data };
        let input_value = encode_message(input).unwrap();

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TRON".to_string(),
            path: "m/44'/195'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
        };
        {
            let map = KEYSTORE_MAP.read();
            let keystore: &Keystore = map.get(&wallet.id).unwrap();
            assert!(keystore.is_locked());
        }

        let ret = call_api("sign_tx", tx).unwrap();
        let output: TronTxOutput = TronTxOutput::decode(ret.as_slice()).unwrap();
        let expected_sign = "bbf5ce0549490613a26c3ac4fc8574e748eabda05662b2e49cea818216b9da18691e78cd6379000e9c8a35c13dfbf620f269be90a078b58799b56dc20da3bdf200";
        assert_eq!(expected_sign, output.signatures[0]);

        {
            let map = KEYSTORE_MAP.read();
            let keystore: &Keystore = map.get(&wallet.id).unwrap();
            assert!(keystore.is_locked());
        }

        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
#[ignore = "this case is test panic"]
fn test_panic_keystore_locked() {
    run_test(|| {
        let wallet = import_default_wallet();
        let param = WalletKeyParam {
            id: wallet.id.to_string(),
            key: Some(api::wallet_key_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let _ret = call_api("unlock_then_crash", param);
        let err = unsafe { _to_str(get_last_err_message()) };
        let err_bytes = Vec::from_hex(err).unwrap();
        let rsp: GeneralResult = GeneralResult::decode(err_bytes.as_slice()).unwrap();
        assert!(!rsp.is_success);
        assert_eq!(rsp.error, "test_unlock_then_crash");
        let map = KEYSTORE_MAP.read();
        let keystore: &Keystore = map.get(&wallet.id).unwrap();
        assert!(keystore.is_locked())
    });
}

#[test]
#[serial]
pub fn test_sign_tezos_tx() {
    run_test(|| {
        let wallet = import_default_wallet();

        let raw_data = "d3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string();
        let input = TezosRawTxIn { raw_data };
        let input_value = encode_message(input).unwrap();
        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password("WRONG PASSWORD".to_string())),
            chain_type: "TEZOS".to_string(),
            path: "m/44'/1729'/0'/0'".to_string(),
            curve: "ed25519".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "password_incorrect");

        let tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TEZOS1".to_string(),
            path: "m/44'/1729'/0'/0'".to_string(),
            curve: "ed25519".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value.clone(),
            }),
        };

        let ret = call_api("sign_tx", tx);
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "unsupported_chain");

        let mut tx = SignParam {
            id: wallet.id.to_string(),
            key: Some(Key::Password(TEST_PASSWORD.to_string())),
            chain_type: "TEZOS".to_string(),
            path: "m/44'/1729'/0'/0'".to_string(),
            curve: "ed25519".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
        };

        let ret = call_api("sign_tx", tx.clone()).unwrap();

        let output: TezosTxOut = TezosTxOut::decode(ret.as_slice()).unwrap();
        let expected_sign = "0df020458bdcfe24546488dd81e1bd7e2cb05379dc7c72ad626646ae22df5d3a652fdc4ffd2383dd5823a98fe158780928da07a3f0a234e23b759ce7b3a39a0c";
        assert_eq!(expected_sign, output.signature.as_str());

        let raw_data = "0xd3bdafa2e36f872e24f1ccd68dbdca4356b193823d0a6a54886d7641e532a2a26c00dedf1a2f428e5e85edf105cb3600949f3d0e8837c70cacb4e803e8528102c0843d0000dcdcf88d0cfb769e33b1888d6bdc351ee3277ea700".to_string();
        let input = TezosRawTxIn { raw_data };
        let input_value = encode_message(input).unwrap();
        tx.input = Some(::prost_types::Any {
            type_url: "imtoken".to_string(),
            value: input_value,
        });
        let ret = call_api("sign_tx", tx).unwrap();
        let output: TezosTxOut = TezosTxOut::decode(ret.as_slice()).unwrap();
        let expected_sign = "0df020458bdcfe24546488dd81e1bd7e2cb05379dc7c72ad626646ae22df5d3a652fdc4ffd2383dd5823a98fe158780928da07a3f0a234e23b759ce7b3a39a0c";
        assert_eq!(expected_sign, output.signature.as_str());
        remove_created_wallet(&wallet.id);
    })
}

#[test]
#[serial]
pub fn test_sign_hashes() {
    run_test(|| {
        let param = ImportMnemonicParam {
            mnemonic: OTHER_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite_id: "".to_string(),
            network: "MAINNET".to_string(),
        };
        let ret = call_api("import_mnemonic", param).unwrap();
        let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();
        let data_to_sign = vec![DataToSign {
            hash: "3e0658d8284d8f50c0aa8fa6cdbd1bde0eb370d4b3489a26c83763671ace8b1c".to_string(),
            path: "m/12381/3600/0/0".to_string(),
            curve: "bls12-381".to_string(),
            sig_alg: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".to_string(),
        }];
        let param = SignHashesParam {
            id: import_result.id.to_string(),
            key: Some(crate::api::sign_hashes_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            data_to_sign,
        };
        let result_bytes = call_api("sign_hashes", param).unwrap();
        let result = SignHashesResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(result.signatures.get(0).unwrap(), "0x8fa5d4dfe4766de7896f0e32c5bee9baae47aaa843cf5f1a2587dd9aaedf8a8c4400cb31bdcb1e90ddfe6d309e57841204dbf53704e4c4da3a9d25e9b4a09dac31a3221a7aac76f58ca21854173303cf58f039770a9e2307966e89faf0e5e79e");

        let data_to_sign = vec![DataToSign {
            hash: "3e0658d8284d8f50c0aa8fa6cdbd1bde0eb370d4b3489a26c83763671ace8b1c".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            sig_alg: "ECDSA".to_string(),
        }];
        let param = SignHashesParam {
            id: import_result.id.to_string(),
            key: Some(crate::api::sign_hashes_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            data_to_sign,
        };
        let result_bytes = call_api("sign_hashes", param).unwrap();
        let result = SignHashesResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(result.signatures.get(0).unwrap(), "0x80c4f5c9299d21dc62a91e6bd1868cda545e31cadbf0eff35f802a4509cecea2618e5b352843ac4f487d2b43ebd55cdf7ad0b78ca81a96504744cd4209ce343d00");

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_sign_ethereum_legacy_tx() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            chain_id: "1".to_string(),
            curve: "secp256k1".to_string(),
        };

        let (wallet, acc_rsp) = import_and_derive(derivation);

        let acc = acc_rsp.accounts.first().unwrap();
        assert_eq!("tpubDCvte6zYB6DKMaEy4fwyoXpuExA4ery3Hu6dVSBZeY9Rg57VKFLwNPMfywWtqRFM1Df5gQJTu42RaaNCgVEyngdVfnYRh9Kb1UCoEYojURc", acc.extended_public_key);
        assert_eq!("w6s0ZvUoPPSiEi1xDMKy5X9+qwhcX4u3e3LOBosJaOSro2ny9jppDxcczZfrhe29n9H3UkmgNoecq/85xfXkGDtH8PMR9iclK5WrcUtkgjXsBcrR6JF0j58i4W9x3y539vXOsLMifCmUr2RcqknDgw==", acc.encrypted_extended_public_key);

        //legacy transaction
        let eth_tx_input = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "1".to_string(),
            tx_type: "".to_string(),
            max_fee_per_gas: "".to_string(),
            max_priority_fee_per_gas: "".to_string(),
            access_list: vec![],
        };
        let input_value = encode_message(eth_tx_input).unwrap();
        let param = SignParam {
            id: wallet.id.to_string(),
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
            key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
        };
        let ret = call_api("sign_tx", param).unwrap();
        let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
        assert_eq!(
            output.tx_hash,
            "0xa0a52398c499ccb09095148188eb027b463de3229f87bfebb8f944606047fd81"
        );
        assert_eq!(output.signature, "f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a06dfc00d1a38acf17137ca1524964ae7e596196703971c6a4d35ada8b09227305a061b8424f251f8724c335fc6df6088db863ee0ea05ebf68ca73a3622aafa19e94");
    })
}

#[test]
#[serial]
pub fn test_sign_ethereum_eip1559_tx() {
    run_test(|| {
        let wallet = import_default_wallet();

        //eip1559 transaction
        let eth_tx_input = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "3490361".to_string(),
            data: "0x200184c0486d5f082a27".to_string(),
            chain_id: "1".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![],
        };
        let input_value = encode_message(eth_tx_input).unwrap();
        let param = SignParam {
            id: wallet.id.to_string(),
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
            key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
        };
        let ret = call_api("sign_tx", param).unwrap();
        let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
        assert_eq!(
            output.tx_hash,
            "0x9a427f295369171f686d83a05b92d8849b822f1fa1c9ccb853e81de545f4625b"
        );
        assert_eq!(output.signature, "02f875010881e285faac6c45d88210be943535353535353535353535353535353535353535833542398a200184c0486d5f082a27c001a0602501c9cfedf145810f9b54558de6cf866a89b7a65890ccde19dd6cec1fe32ca02769f3382ee526a372241238922da39f6283a9613215fd98c8ce37a0d03fa3bb");
    })
}

#[test]
#[serial]
pub fn test_sign_ethereum_eip1559_tx2() {
    run_test(|| {
        let wallet = import_default_wallet();
        //eip1559 transaction
        let mut access_list = vec![];
        access_list.push(AccessList {
            address: "0x019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
            storage_keys: vec![],
        });
        access_list.push(AccessList {
            address: "0x1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
            storage_keys: vec![
                "0xd259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2".to_string(),
            ],
        });
        access_list.push(AccessList {
            address: "0xf1946eba70f89687d67493d8106f56c90ecba943".to_string(),
            storage_keys: vec![
                "0xb3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9".to_string(),
                "0x6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82".to_string(),
                "0x0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064".to_string(),
            ],
        });
        let eth_tx_input = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "3490361".to_string(),
            data: "0x200184c0486d5f082a27".to_string(),
            chain_id: "1".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list,
        };
        let input_value = encode_message(eth_tx_input).unwrap();
        let param = SignParam {
            id: wallet.id.to_string(),
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
            key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
        };
        let ret = call_api("sign_tx", param).unwrap();
        let output: EthTxOutput = EthTxOutput::decode(ret.as_slice()).unwrap();
        assert_eq!(
            output.tx_hash,
            "0x2c20edff7e496c1f8d8370fc3d70f3f02b4c63008bb2586d507ddb88d68cea7d"
        );
        assert_eq!(output.signature, "02f90141010881e285faac6c45d88210be943535353535353535353535353535353535353535833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a0d95cb4d82912b2fed0510dd44cce5c0b177af6e7ed991f1dbe5b8e34303bf84ca04e0896caf07d9644e2728d919a84f7af46cb2421a0ce7bb814cce782d921e672");
    })
}

#[test]
#[serial]
pub fn test_sign_ethereum_sign_message() {
    run_test(|| {
        let wallet = import_default_wallet();

        let eth_tx_input = EthMessageInput {
            message: "0x4578616d706c652060706572736f6e616c5f7369676e60206d657373616765".to_string(),
            signature_type: 0i32,
        };
        let input_value = encode_message(eth_tx_input).unwrap();
        let param = SignParam {
            id: wallet.id.to_string(),
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
            input: Some(::prost_types::Any {
                type_url: "imtoken".to_string(),
                value: input_value,
            }),
            key: Some(sign_param::Key::Password(sample_key::PASSWORD.to_string())),
        };
        let ret = call_api("sign_msg", param).unwrap();
        let output: EthMessageOutput = EthMessageOutput::decode(ret.as_slice()).unwrap();

        assert_eq!(output.signature, "0x5d595524847790aade63630ba4320854e0ae474b50d4c83eadfea9179185b2d67479cdfa9f59ec8f62575a7c09d4a5c9683aaf9cdb198ee51bdbe1bbf6eed1e91b");
    })
}

#[test]
#[serial]
pub fn test_sign_bls_to_execution_change() {
    run_test(|| {
        let param = ImportMnemonicParam {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_string(),
                password: TEST_PASSWORD.to_string(),
                name: "test-wallet".to_string(),
                password_hint: "imtoken".to_string(),
                 overwrite_id: "".to_string(),
                network: "MAINNET".to_string(),
            };
        let ret = call_api("import_mnemonic", param).unwrap();
        let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

        let derivations = vec![PublicKeyDerivation {
            path: "m/12381/3600/0/0".to_string(),
            curve: "bls12-381".to_string(),
            chain_type: "ETHEREUM2".to_string(),
        }];
        let param = GetPublicKeysParam {
            id: import_result.id.to_string(),
            key: Some(crate::api::get_public_keys_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations,
        };
        let result_bytes = call_api("get_public_keys", param).unwrap();
        let result = GetPublicKeysResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(result.public_keys.clone().get(0).unwrap(), "0x99b1f1d84d76185466d86c34bde1101316afddae76217aa86cd066979b19858c2c9d9e56eebc1e067ac54277a61790db");

        let mut param = SignBlsToExecutionChangeParam {
            id: import_result.id.to_string(),
            key: Some(
                tcx_eth2::transaction::sign_bls_to_execution_change_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                ),
            ),
            genesis_fork_version: "0x03000000".to_string(),
            genesis_validators_root:
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            validator_index: vec![0],
            from_bls_pub_key: result.public_keys.get(0).unwrap().to_owned(),
            eth1_withdrawal_address: "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15".to_string(),
        };
        let ret_bytes = call_api("sign_bls_to_execution_change", param.clone()).unwrap();
        let result: SignBlsToExecutionChangeResult =
            SignBlsToExecutionChangeResult::decode(ret_bytes.as_slice()).unwrap();

        assert_eq!(result.signeds.get(0).unwrap().signature, "8c8ce9f8aedf380e47548501d348afa28fbfc282f50edf33555a3ed72eb24d710bc527b5108022cffb764b953941ec4014c44106d2708387d26cc84cbc5c546a1e6e56fdc194cf2649719e6ac149596d80c86bf6844b36bd47038ee96dd3962f");
        param.eth1_withdrawal_address = "0x8c1Ff978036F2e9d7CC382Eff7B4c8c53C22ac15XX".to_string();
        let result = call_api("sign_bls_to_execution_change", param.clone());
        assert_eq!(
            result.err().unwrap().to_string(),
            "invalid_eth_address".to_string()
        );
        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
fn test_eth_batch_personal_sign_by_private_key() {
    run_test(|| {
        let wallet = import_default_pk_store();
        let param = EthBatchPersonalSignParam {
            id: wallet.id.to_string(),
            key: Some(api::eth_batch_personal_sign_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            data: vec![
                "Hello imToken".to_string(),
                "0xef678007d18427e6022059dbc264f27507cd1ffc".to_string(),
            ],
            path: "".to_string(),
        };
        let sign_result = call_api("eth_batch_personal_sign", param).unwrap();
        let ret: EthBatchPersonalSignResult =
            EthBatchPersonalSignResult::decode(sign_result.as_slice()).unwrap();
        assert_eq!(ret.signatures[0], "0x1be38ff0ab0e6d97cba73cf61421f0641628be8ee91dcb2f73315e7fdf4d0e2770b0cb3cc7350426798d43f0fb05602664a28bb2c9fcf46a07fa1c8c4e322ec01b".to_string());
        assert_eq!(ret.signatures[1], "0xb12a1c9d3a7bb722d952366b06bd48cb35bdf69065dee92351504c3716a782493c697de7b5e59579bdcc624aa277f8be5e7f42dc65fe7fcd4cc68fef29ff28c21b".to_string());
    });
}

#[test]
#[serial]
fn test_eth_batch_personal_sign_by_hd() {
    run_test(|| {
        let wallet = import_default_wallet();
        let param = EthBatchPersonalSignParam {
            id: wallet.id.to_string(),
            key: Some(api::eth_batch_personal_sign_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            data: vec![
                "Hello imToken".to_string(),
                "0xef678007d18427e6022059dbc264f27507cd1ffc".to_string(),
            ],
            path: "".to_string(),
        };
        let sign_result = call_api("eth_batch_personal_sign", param).unwrap();
        let ret: EthBatchPersonalSignResult =
            EthBatchPersonalSignResult::decode(sign_result.as_slice()).unwrap();
        assert_eq!(ret.signatures[0], "0xb270b1e5ee1345c693b7b4fd7f5287f6b6372059c89590dfcadc4edf94ec9293296d3e205495f1468953a4f893cd6798b66301a51571fe2a419e75d5755b5bc91c".to_string());
        assert_eq!(ret.signatures[1], "0x19671e4c92847629fa5bbba59e70402f54366e61db0555984a83cc512413fc462d6be1508f1accdee6ad0040ed7401ac2db33d17e1aa4e66bedcb9f75c250cfa1b".to_string());

        let param = EthBatchPersonalSignParam {
            id: wallet.id.to_string(),
            key: Some(api::eth_batch_personal_sign_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            data: vec![
                "Please sign this message with your Ethereum account: 0x0d3Dfa13F3C0eD29A68012352C71E5695Ef3f9fc

I confirm that I want to unstake and exit this validator: 0xb9a451e8e71d1b62d00355103768c4a2eeedb5e95b127f7145c284adcd0a9c1b1b5224ac73d6555c3962b03f9840942a

Chain ID: 5
Issued At: 2024-02-27T06:45:12.725Z".to_string(),
            ],
            path: "m/44'/60'/0'/0/0".to_string(),
        };
        let sign_result = call_api("eth_batch_personal_sign", param).unwrap();
        let ret: EthBatchPersonalSignResult =
            EthBatchPersonalSignResult::decode(sign_result.as_slice()).unwrap();
        assert_eq!(ret.signatures[0], "0xa30a252dd84370a22035b1bdd43e594bb54c3e874f3cee2b4c12e16392feb3c13d4589d3f2b006fcad20426a4cb2b16c3523cc82705d1e447a9926cb1e2398481c".to_string());
    });
}
