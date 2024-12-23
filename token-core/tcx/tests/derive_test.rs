use common::run_test;
use serial_test::serial;

mod common;

use tcx::api::derive_accounts_param::Derivation;

use tcx::*;

use prost::Message;
use tcx::api::{
    DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
    GetExtendedPublicKeysParam, GetExtendedPublicKeysResult, GetPublicKeysParam,
    GetPublicKeysResult, ImportMnemonicParam, ImportPrivateKeyParam, ImportPrivateKeyResult,
    KeystoreResult, MnemonicToPublicKeyParam, MnemonicToPublicKeyResult, PublicKeyDerivation,
};
use tcx::handler::encode_message;
use tcx::handler::import_mnemonic;
use tcx_constants::{OTHER_MNEMONIC, TEST_MNEMONIC, TEST_PASSWORD};
use tcx_constants::{TEST_PRIVATE_KEY, TEST_WIF};

use sp_core::ByteArray;
use tcx::api::derive_accounts_param::Key::Password;

use tcx::handler::*;

use crate::common::*;

#[test]
#[serial]
pub fn test_derive_accounts() {
    run_test(|| {
        let param = ImportMnemonicParam {
            mnemonic: OTHER_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            network: "TESTNET".to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite_id: "".to_string(),
        };
        let ret = call_api("import_mnemonic", param).unwrap();
        let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();

        let derivations = vec![
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/49'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "m/49'/1'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "TRON".to_string(),
                path: "m/44'/195'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "NERVOS".to_string(),
                path: "m/44'/309'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "//kusama//imToken/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "//polkadot//imToken/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/44'/461'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "FILECOIN".to_string(),
                path: "m/12381/461/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "bls12-381".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "COSMOS".to_string(),
                path: "m/44'/118'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "cosmoshub-4".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "ETHEREUM".to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/44'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/49'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/84'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_0".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "BITCOIN".to_string(),
                path: "m/86'/0'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "TEZOS".to_string(),
                path: "m/44'/1729'/0'/0'".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "ed25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "DOGECOIN".to_string(),
                path: "m/44'/3'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "DOGECOIN".to_string(),
                path: "m/44'/1'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "DOGECOIN".to_string(),
                path: "m/44'/1'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "VERSION_1".to_string(),
                chain_id: "".to_string(),
                curve: "secp256k1".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "TON".to_string(),
                path: "m/44'/607'/0'".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "ed25519".to_string(),
                contract_code: "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=".to_string(),
            },
        ];

        let param = DeriveAccountsParam {
            id: import_result.id.to_string(),
            key: Some(crate::api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations,
        };
        let derived_accounts_bytes = call_api("derive_accounts", param).unwrap();
        let derived_accounts: DeriveAccountsResult =
            DeriveAccountsResult::decode(derived_accounts_bytes.as_slice()).unwrap();
        assert_eq!(21, derived_accounts.accounts.len());
        assert_eq!(
            "LQ3JqCohgLQ3x1CJXYERnJTy1ySaqr1E32",
            derived_accounts.accounts[0].address
        );
        assert_eq!("/EhDRyPFcj1UGx8i+WiJSIeBSyaN0pX7Oq3wXqwO5M9T1aRhfLpsNPGAPLf07K+p+B0OdQW1ogVbDQCWkIwVXZLPY+njp9LjXaICiWGEeidR1TwBZSwOMRKE68wJWH/7puxYfY/Rq1+d2GFv6NxSCw==", derived_accounts.accounts[0].encrypted_extended_public_key);
        assert_eq!("xpub6BwqzNhMbFpgegP8WGBzFmm7aUsrDQtuuRdT3J3nDhDGnbPCER8qGghKJUCJNhjn2wyZVwAC6mwLNPu9xQpeQenqnzzVj2X7tnDLAM58fRn", derived_accounts.accounts[0].extended_public_key);

        assert_eq!(
            "MQUu6P7wsLQZfVZMuFWB7UXiheuVTM7RYF",
            derived_accounts.accounts[1].address
        );
        //            assert_eq!("5wlT8R+syH37UjMSJXOW3v96ORRykslaBOX7wa+aEt4jbshR9ljP5u+DDskzV5hAKuSBuIPftafEA/k4YQ4Zh2mByl0EE/5jdZI/ZbE0a2zsIiU9BIGuhzA/f+vvQuDJqOHofDd8z0qDesuqxLKv4A==", derived_accounts.accounts[1].encrypted_extended_public_key);
        assert_eq!("A5LUzJcPB4r54wqr8EjFh9fe0L87spIN9KJKtzHV6QJXBH6GEAiYT57uftpJITx613HdIXXzi8VJ30TmG8erBF30oD1DnbDmGmDo4sdRTdQSsp9NuprhZ3Y3PR9+xzdc2tKDblRL5dLZswaPxCOQcw==", derived_accounts.accounts[1].encrypted_extended_public_key);

        assert_eq!(
            "mvdDMnRsqjqzvCyYyRXpvscmnU1FxodhkE",
            derived_accounts.accounts[2].address
        );
        assert_eq!("eZIL4e0a8qw18Pve92iLfehteHDA+kqjwv91aKE+2hNN3arkq20yY2Mx6q4WAowFv0QRfIi6QlrhafJKUpjiC469NNZagCSHLaECYliEwmwTgC97zXmVJDB6MJi79y+mznf8G7Few8+u6UfiXELN5g==", derived_accounts.accounts[2].encrypted_extended_public_key);

        assert_eq!(
            "TLZnqkrSNLUWNrZMug8u9b6pJ3XcTGbzDV",
            derived_accounts.accounts[3].address
        );
        assert_eq!("Sla41n5BdHqc1QmqA9DXjWNx13Fpq18u19jCaMbYbxClsPr7cr/gzXsbE+08wfNLuGgtVVY4/prpnv3/pdJ8KA/I/iOKvelKxuJgN9n2O5Q54CmObc0qJVZxcAQM0PbrKE9YJyGDkJNMLM+OmjEwjg==", derived_accounts.accounts[3].encrypted_extended_public_key);

        assert_eq!(
            "ckt1qyqgkffut7e7md39tp5ts9vxssj7wdw8z4cquyflka",
            derived_accounts.accounts[4].address
        );

        assert_eq!(
            "HFEP5ePp69xrCLTYcDnzqJTgmH87RUKprkoRUuEmu9Tk49s",
            derived_accounts.accounts[5].address
        );
        assert_eq!(
            "13GVaZUS28zTCroTPq8dyppfm8F4cAvoJsSZ3yvmtyRYLSLJ",
            derived_accounts.accounts[6].address
        );
        assert_eq!(
            "t1k7yhkb42jhgrsx4nhr7rfkxfiahmkyxq5cw74ry",
            derived_accounts.accounts[7].address
        );
        assert_eq!(
            "t3qnoxt4gpoyahbgmh2n2cvpeqoqa7jowlyxyuo3jgedp4gdyauhvcydd6var2d3i6yyrdhpqsixqxozp7b64a",
            derived_accounts.accounts[8].address
        );
        assert_eq!(
            "cosmos1m566v5rcklnac8vc0dftfu4lnvznhlu7d3f404",
            derived_accounts.accounts[9].address
        );

        assert_eq!("", derived_accounts.accounts[10].address);
        assert_eq!(
            "EOS7Nf9TU1vZaQQgZA3cELTHJf1nnDJ6xVvqHvVzbHehsgcjrzNkq",
            derived_accounts.accounts[10].public_key
        );
        assert_eq!(
            "0x37c6713aa848bCdeE372A620eEbCdcCBA55c695F",
            derived_accounts.accounts[11].address
        );
        assert_eq!(
            "1PHNSh4M6uLqJfiDWZRj4w2F2LXSaygVtE",
            derived_accounts.accounts[12].address
        );
        assert_eq!(
            "3CwQ11hx8yT6eGXqQJBFCRxZ8eCnLd9wZj",
            derived_accounts.accounts[13].address
        );
        assert_eq!(
            "bc1qk5ctv049qsavhh6ykygnm43mjuk5v26jd34qgq",
            derived_accounts.accounts[14].address
        );
        assert_eq!(
            "bc1phazpdjkaruvcqhaakmk56tvmqcd4kx5svvrjdrck5m7g3q2uadpszxypw0",
            derived_accounts.accounts[15].address
        );

        assert_eq!(
            "tz1YhnU6rUigVp6Jei1VJQHofGSbzGKphVmG",
            derived_accounts.accounts[16].address
        );

        assert_eq!(
            "DGUrMnbLGQzZV3H1AYackWuykSKqqUMGEf",
            derived_accounts.accounts[17].address
        );
        assert_eq!(
            "DP48ckynvMTDkxC7SEvxtDztyFmZxviDCf",
            derived_accounts.accounts[18].address
        );
        assert_eq!(
            "1p37xv5xzd92c4wh8zt96f77a8jlf3n2qh4cps03xgurmpnllxy5us2dwgfl",
            derived_accounts.accounts[19].address
        );
        assert_eq!(
            "UQDt6ko7K8TqHga_KO5fsKr-vrIz5EyuhpX1NrERE4UOg4CG",
            derived_accounts.accounts[20].address
        );

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_hd_store_derive_invalid_param() {
    run_test(|| {
        let import_result: KeystoreResult = import_default_wallet();

        let invalid_derivations = vec![
            Derivation {
                chain_type: "WRONG_CHAIN_TYPE".to_string(),
                path: "m/44'/2'/0'/0/0".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "WRONG/PATH".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "P2WPKH".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "LITECOIN".to_string(),
                path: "49'/1'/0'/0/0".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
                chain_id: "".to_string(),
                curve: "".to_string(),
                contract_code: "".to_string(),
            },
        ];
        for derivation in invalid_derivations {
            let param = DeriveAccountsParam {
                id: import_result.id.to_string(),
                key: Some(crate::api::derive_accounts_param::Key::Password(
                    TEST_PASSWORD.to_owned(),
                )),
                derivations: vec![derivation],
            };
            let ret = call_api("derive_accounts", param);
            assert!(ret.is_err());
        }

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_get_public_keys() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param: GetPublicKeysParam = GetPublicKeysParam {
            id: wallet.id.to_string(),
            key: Some(crate::api::get_public_keys_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations: vec![PublicKeyDerivation {
                chain_type: "EOS".to_string(),
                path: "m/44'/194'/0'/0/0".to_string(),
                curve: "secp256k1".to_string(),
            }],
        };
        let ret_bytes = call_api("get_public_keys", param).unwrap();
        let public_key_result: GetPublicKeysResult =
            GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            public_key_result.public_keys[0]
        );
    })
}

#[test]
#[serial]
pub fn test_get_public_keys_ethereum2() {
    run_test(|| {
        let wallet = import_default_wallet();

        let param: GetPublicKeysParam = GetPublicKeysParam {
            id: wallet.id.to_string(),
            key: Some(crate::api::get_public_keys_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations: vec![PublicKeyDerivation {
                chain_type: "ETEHREUM2".to_string(),
                path: "m/12381/3600/0/0".to_string(),
                curve: "bls12-381".to_string(),
            }],
        };
        let ret_bytes = call_api("get_public_keys", param).unwrap();
        let public_key_result: GetPublicKeysResult =
            GetPublicKeysResult::decode(ret_bytes.as_slice()).unwrap();
        assert_eq!(
            "0x99833eeee8cfad1bb7a82a5ceecca02590eeb342ad491c64c270fdb9bd739c398b7f8ca8608bfada25ba4efb5d8e5653",
            public_key_result.public_keys[0]
        );
    })
}

#[test]
#[serial]
pub fn test_get_pubkey_keys() {
    run_test(|| {
        let param = ImportMnemonicParam {
            mnemonic: OTHER_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite_id: "".to_string(),
            network: "TESTNET".to_string(),
        };
        let ret = call_api("import_mnemonic", param).unwrap();
        let import_result: KeystoreResult = KeystoreResult::decode(ret.as_slice()).unwrap();
        let derivations = vec![PublicKeyDerivation {
            chain_type: "ETHEREUM2".to_string(),
            path: "m/12381/3600/0/0/0".to_string(),
            curve: "bls12-381".to_string(),
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
        assert_eq!(result.public_keys.get(0).unwrap(), "0x941c2ab3d28b0fe37fde727e3178738a475696aed7335c7f4c2d91d06a1540acadb8042f119fb5f8029e7765de21fac2");

        remove_created_wallet(&import_result.id);
    })
}

#[test]
#[serial]
pub fn test_derive_btc_legacy_sub_accounts() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "BITCOIN".to_string(),
            path: "m/44'/0'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            contract_code: "".to_string(),
        };

        let (_wallet, accounts) = import_and_derive(derivation);
        let params = DeriveSubAccountsParam {
            chain_id: "".to_string(),
            chain_type: "BITCOIN".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string(), "1/0".to_string()],
            extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
        };

        let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
            result.accounts[0].address
        );
        assert_eq!(
            "1962gsZ8PoPUYHneFakkCTrukdFMVQ4i4T",
            result.accounts[1].address
        );
        assert_eq!(
            "19vddWhyq637bqDfuKadsoy5mTNRgfb3hr",
            result.accounts[2].address
        );
    })
}

#[test]
#[serial]
pub fn test_derive_btc_p2wpkh_sub_accounts() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "BITCOIN".to_string(),
            path: "m/49'/0'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            contract_code: "".to_string(),
        };

        let (_wallet, accounts) = import_and_derive(derivation);
        let params = DeriveSubAccountsParam {
            chain_id: "".to_string(),
            chain_type: "BITCOIN".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "P2WPKH".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string(), "1/0".to_string()],
            extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
        };

        let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "3JmreiUEKn8P3SyLYmZ7C1YCd4r2nFy3Dp",
            result.accounts[0].address
        );
        assert_eq!(
            "33xJxujVGf4qBmPTnGW9P8wrKCmT7Nwt3t",
            result.accounts[1].address
        );
        assert_eq!(
            "33K4nJ6HuM4fuJct11xPPHH65dnGrN5Ggt",
            result.accounts[2].address
        );
    })
}

#[test]
#[serial]
pub fn test_derive_eth_sub_accounts() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "ETHEREUM".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "".to_string(),
            curve: "secp256k1".to_string(),
            contract_code: "".to_string(),
        };

        let (_, accounts) = import_and_derive(derivation);
        let params = DeriveSubAccountsParam {
            chain_id: "".to_string(),
            chain_type: "ETHEREUM".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
        };

        let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b",
            result.accounts[0].address
        );
        assert_eq!(
            "0x80427Ae1f55bCf60ee4CD2db7549b8BC69a74303",
            result.accounts[1].address
        );
    })
}

#[test]
#[serial]
pub fn test_derive_cosmos_sub_accounts() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "COSMOS".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "cosmoshub-4".to_string(),
            curve: "secp256k1".to_string(),
        };

        let (_, accounts) = import_and_derive(derivation);
        let params = DeriveSubAccountsParam {
            chain_id: "cosmoshub-4".to_string(),
            chain_type: "COSMOS".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
        };

        let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992",
            result.accounts[0].address
        );
        assert_eq!(
            "cosmos1nkujjlktqdue52xc0k09yzc7h3xswsfpl568zc",
            result.accounts[1].address
        );

        let params = DeriveSubAccountsParam {
            chain_id: "osmosis-1".to_string(),
            chain_type: "COSMOS".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: accounts.accounts[0].extended_public_key.to_string(),
        };

        let result_bytes = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let result = DeriveSubAccountsResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "osmo1ajz9y0x3wekez7tz2td2j6l2dftn28v2jk74nc",
            result.accounts[0].address
        );
        assert_eq!(
            "osmo1nkujjlktqdue52xc0k09yzc7h3xswsfph0fh52",
            result.accounts[1].address
        )
    })
}

#[test]
#[serial]
pub fn test_derive_verify_hrp() {
    run_test(|| {
        let derivation = Derivation {
            chain_type: "COSMOS".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "osmosis-2".to_string(),
            curve: "secp256k1".to_string(),
        };

        let wallet = import_default_wallet();

        let derivation_param = DeriveAccountsParam {
            id: wallet.id.to_string(),
            derivations: vec![derivation],
            key: Some(Password(TEST_PASSWORD.to_string())),
        };

        let result = derive_accounts(&encode_message(derivation_param).unwrap());
        assert_eq!(format!("{}", result.err().unwrap()), "unknown_chain_id");

        let derivation = Derivation {
            chain_type: "COSMOS".to_string(),
            path: "m/44'/118'/0'/0/0".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            chain_id: "cosmoshub-4".to_string(),
            curve: "secp256k1".to_string(),
        };

        let derivation_param = DeriveAccountsParam {
            id: wallet.id.to_string(),
            derivations: vec![derivation],
            key: Some(Password(TEST_PASSWORD.to_string())),
        };

        let result = derive_accounts(&encode_message(derivation_param).unwrap()).unwrap();

        let account = DeriveAccountsResult::decode(result.as_slice()).unwrap();
        assert_eq!(
            account.accounts[0].address,
            "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992"
        );

        let params = DeriveSubAccountsParam {
            chain_id: "osmosis-1".to_string(),
            chain_type: "COSMOS".to_string(),
            curve: "secp256k1".to_string(),
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
            relative_paths: vec!["0/0".to_string(), "0/1".to_string()],
            extended_public_key: account.accounts[0].extended_public_key.to_string(),
        };

        let result = derive_sub_accounts(&encode_message(params).unwrap()).unwrap();
        let account = DeriveAccountsResult::decode(result.as_slice()).unwrap();
        assert_eq!(
            account.accounts[0].address,
            "osmo1ajz9y0x3wekez7tz2td2j6l2dftn28v2jk74nc"
        );
    })
}

#[test]
#[serial]
pub fn test_mnemonic_to_public() {
    run_test(|| {
        let params = MnemonicToPublicKeyParam {
            mnemonic: TEST_MNEMONIC.to_string(),
            path: "m/44'/194'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            encoding: "EOS".to_string(),
        };

        let result_bytes = mnemonic_to_public(&encode_message(params).unwrap()).unwrap();
        let result = MnemonicToPublicKeyResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF",
            result.public_key
        );

        let params = MnemonicToPublicKeyParam {
            mnemonic: TEST_MNEMONIC.to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
            encoding: "HEX".to_string(),
        };

        let result_bytes = mnemonic_to_public(&encode_message(params).unwrap()).unwrap();
        let result = MnemonicToPublicKeyResult::decode(result_bytes.as_slice()).unwrap();
        assert_eq!(
            "0x0280c98b8ea7cab630defb0c09a4295c2193cdee016c1d5b9b0cb18572b9c370fe",
            result.public_key
        );
    })
}

#[test]
#[serial]
pub fn test_get_extended_public_keys() {
    run_test(|| {
        let wallet = import_default_wallet();
        let derivations = vec![PublicKeyDerivation {
            chain_type: "BITCOIN".to_string(),
            path: "m/44'/145'/0'/0/0".to_string(),
            curve: "secp256k1".to_string(),
        }];
        let param = GetExtendedPublicKeysParam {
            id: wallet.id,
            derivations,
            key: Some(api::get_extended_public_keys_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
        };
        let ret = call_api("get_extended_public_keys", param).unwrap();
        let resp: GetExtendedPublicKeysResult =
            GetExtendedPublicKeysResult::decode(ret.as_slice()).unwrap();
        assert_eq!(resp.extended_public_keys.get(0).unwrap(), "xpub6GZjFnyumLtEwC4KQkigvc3vXJdZvy71QxHTsFQQv1YtEUWNEwynKWsK2LBFZNLWdTk3w1Y9cRv4NN7V2pnDBoWgH3PkVE9r9Q2kSQL2zkH");
    })
}

#[test]
#[serial]
fn polkadotjs_cross_test() {
    run_test(|| {
        let param = ImportMnemonicParam {
            mnemonic: TEST_MNEMONIC.to_string(),
            password: TEST_PASSWORD.to_string(),
            network: "TESTNET".to_string(),
            name: "test-wallet".to_string(),
            password_hint: "imtoken".to_string(),
            overwrite_id: "".to_string(),
        };
        let ret = import_mnemonic(&encode_message(param).unwrap()).unwrap();
        let wallet = KeystoreResult::decode(ret.as_slice()).unwrap();

        let derivations = vec![
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "//imToken//polakdot/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "//imToken//polakdot/0/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "//imToken//polakdot/0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "//imToken//polakdot/0//1".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "KUSAMA".to_string(),
                path: "//0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
            Derivation {
                chain_type: "POLKADOT".to_string(),
                path: "//0".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
                chain_id: "".to_string(),
                curve: "sr25519".to_string(),
                contract_code: "".to_string(),
            },
        ];
        let param = DeriveAccountsParam {
            id: wallet.id.to_string(),
            key: Some(crate::api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_owned(),
            )),
            derivations,
        };
        let expected = vec![
            "148fArFqHEtURxdvYAtLkSUkuHxqzPGsaC7Ro1zaUWFJ5dNF",
            "15YFBQp1kUWEXm22QXySuWyVZckk7QCZiuBfENLAfmbevstt",
            "16hsF1UW1kob7vUR7tymVNCmp1eo18uhhtc4szetH4xbYpbd",
            "FhygqLe3pdvk5SrMEePWF1cCGFS6kXux5Dh2PHBQDSGeJSW",
            "EkkpqYe4XGLst9o8NhvFRhMwto7MNxrsW9vboMzffdwUW3F",
            "JHBkzZJnLZ3S3HLvxjpFAjd6ywP7WAk5miL7MwVCn9a7jHS",
            "JKZKcChQMRYd4zFdeSL5DX3EPNMtaLqAddnycJ4gEL2kJTK",
            "16kEod7tdmg6JxBKpagHKQzBwR5mnD5nnkXXkF1TkX94BooY",
        ];

        let ret = call_api("derive_accounts", param).unwrap();
        let result: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();
        assert_eq!(result.accounts.len(), 8);
        for (index, account) in result.accounts.iter().enumerate() {
            assert_eq!(account.address, expected[index]);
        }
    })
}

#[test]
#[serial]
fn test_derive_other_curve_on_pk_keystore() {
    run_test(|| {
        let param = ImportPrivateKeyParam {
            password: TEST_PASSWORD.to_string(),
            private_key: TEST_PRIVATE_KEY.to_string(),
            name: "hex pk".to_string(),
            password_hint: "".to_string(),
            network: "".to_string(),
            overwrite_id: "".to_string(),
        };
        let ret = call_api("import_private_key", param).unwrap();
        let imported = ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();

        let derive_param = DeriveAccountsParam {
            id: imported.id.to_string(),
            derivations: vec![
                Derivation {
                    chain_type: "ETHEREUM".to_string(),
                    chain_id: "".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    curve: "secp256k1".to_string(),
                    seg_wit: "".to_string(),
                    contract_code: "".to_string(),
                },
                Derivation {
                    chain_type: "FILECOIN".to_string(),
                    chain_id: "".to_string(),
                    path: "".to_string(),
                    network: "".to_string(),
                    curve: "secp256k1".to_string(),
                    seg_wit: "".to_string(),
                    contract_code: "".to_string(),
                },
            ],
            key: Some(api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("derive_accounts", derive_param).unwrap();
        let accounts = DeriveAccountsResult::decode(ret.as_slice()).unwrap();
        assert_eq!(
            accounts.accounts[0].address,
            "0x6031564e7b2F5cc33737807b2E58DaFF870B590b"
        );
        assert_eq!(
            accounts.accounts[1].address,
            "t1cwgcugpo6lmjw2h4kwxei7i7lqcuth3en3h4eli"
        );

        let derive_param = DeriveAccountsParam {
            id: imported.id.to_string(),
            derivations: vec![Derivation {
                chain_type: "TEZOS".to_string(),
                chain_id: "".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                curve: "ed25519".to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            }],
            key: Some(api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("derive_accounts", derive_param);
        assert_eq!(
            format!("{}", ret.err().unwrap()),
            "private_key_curve_not_match"
        );

        let derive_param = DeriveAccountsParam {
            id: imported.id.to_string(),
            derivations: vec![Derivation {
                chain_type: "KUSAMA".to_string(),
                chain_id: "".to_string(),
                path: "".to_string(),
                network: "".to_string(),
                curve: "sr25519".to_string(),
                seg_wit: "".to_string(),
                contract_code: "".to_string(),
            }],
            key: Some(api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("derive_accounts", derive_param);
        assert_eq!(
            format!("{}", ret.err().unwrap()),
            "private_key_curve_not_match"
        );
    })
}

#[test]
#[serial]
fn test_derive_mainnet_account_on_test_wif() {
    run_test(|| {
        let param = ImportPrivateKeyParam {
            password: TEST_PASSWORD.to_string(),
            private_key: TEST_WIF.to_string(),
            name: "wif".to_string(),
            password_hint: "".to_string(),
            network: "MAINNET".to_string(),
            overwrite_id: "".to_string(),
        };
        let ret = call_api("import_private_key", param).unwrap();
        let imported = ImportPrivateKeyResult::decode(ret.as_slice()).unwrap();

        let derive_param = DeriveAccountsParam {
            id: imported.id.to_string(),
            derivations: vec![Derivation {
                chain_type: "BITCOIN".to_string(),
                chain_id: "".to_string(),
                path: "".to_string(),
                network: "TESTNET".to_string(),
                curve: "secp256k1".to_string(),
                seg_wit: "VERSION_1".to_string(),
                contract_code: "".to_string(),
            }],
            key: Some(api::derive_accounts_param::Key::Password(
                TEST_PASSWORD.to_string(),
            )),
        };
        let ret = call_api("derive_accounts", derive_param).unwrap();
        let accounts = DeriveAccountsResult::decode(ret.as_slice()).unwrap();
        assert_eq!(
            accounts.accounts[0].address,
            "tb1pqpae4d6594jj3yueluku5tlu7r6nqwm24xc8thk5g396s9e5anvqdwrut7"
        );
    })
}
