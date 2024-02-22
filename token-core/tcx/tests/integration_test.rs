use common::run_test;
use serial_test::serial;
use tcx::api::TcxAction;

mod common;
use api::sign_param::Key;
use error_handling::Result;
use std::ffi::{CStr, CString};
use std::fs::remove_file;
use std::os::raw::c_char;
use std::panic;
use std::path::Path;
use tcx::api::derive_accounts_param::Derivation;
use tcx::api::sign_hashes_param::DataToSign;
use tcx::filemanager::KEYSTORE_MAP;
use tcx::handler::scan_keystores;
use tcx::*;
use tcx_atom::transaction::{AtomTxInput, AtomTxOutput};
use tcx_common::ToHex;
use tcx_eth2::transaction::{SignBlsToExecutionChangeParam, SignBlsToExecutionChangeResult};
use tcx_keystore::keystore::IdentityNetwork;

use prost::Message;
use tcx::api::{
    export_mnemonic_param, export_private_key_param, migrate_keystore_param, sign_param,
    BackupResult, CreateKeystoreParam, DecryptDataFromIpfsParam, DecryptDataFromIpfsResult,
    DeriveAccountsParam, DeriveAccountsResult, DeriveSubAccountsParam, DeriveSubAccountsResult,
    DerivedKeyResult, EncryptDataToIpfsParam, EncryptDataToIpfsResult, ExistsJsonParam,
    ExistsKeystoreResult, ExistsMnemonicParam, ExistsPrivateKeyParam, ExportJsonParam,
    ExportJsonResult, ExportMnemonicParam, ExportMnemonicResult, ExportPrivateKeyParam,
    ExportPrivateKeyResult, GeneralResult, GetExtendedPublicKeysParam, GetExtendedPublicKeysResult,
    GetPublicKeysParam, GetPublicKeysResult, ImportJsonParam, ImportMnemonicParam,
    ImportPrivateKeyParam, ImportPrivateKeyResult, InitTokenCoreXParam, KeystoreResult,
    MigrateKeystoreParam, MigrateKeystoreResult, MnemonicToPublicKeyParam,
    MnemonicToPublicKeyResult, PublicKeyDerivation, SignAuthenticationMessageParam,
    SignAuthenticationMessageResult, SignHashesParam, SignHashesResult, SignParam, WalletKeyParam,
};
use tcx::handler::import_mnemonic;
use tcx::handler::{encode_message, import_private_key};
use tcx_constants::{sample_key, CurveType, TEST_PRIVATE_KEY, TEST_WIF};
use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
use tcx_keystore::Keystore;

use std::fs;
use tcx_btc_kin::transaction::BtcKinTxInput;

use sp_core::ByteArray;
use sp_runtime::traits::Verify;
use tcx_btc_kin::{OmniTxInput, Utxo};
use tcx_ckb::{CachedCell, CellInput, CkbTxInput, CkbTxOutput, OutPoint, Script, Witness};

use anyhow::anyhow;
use tcx_common::hex::FromHex;
use tcx_eth::transaction::{
    AccessList, EthMessageInput, EthMessageOutput, EthTxInput, EthTxOutput,
};
use tcx_filecoin::{SignedMessage, UnsignedMessage};
use tcx_substrate::{SubstrateKeystore, SubstrateRawTxIn, SubstrateTxOut};
use tcx_tezos::transaction::{TezosRawTxIn, TezosTxOut};
use tcx_tron::transaction::{TronMessageInput, TronMessageOutput, TronTxInput, TronTxOutput};

use crate::common::import_default_wallet;

#[test]
#[serial]
#[ignore = "for debug"]
fn test_call_tcx_api() {
    run_test(|| {
        let bytes = &Vec::<u8>::from_hex_auto("0a077369676e5f747812c6020a0d6170692e5369676e506172616d12b4020a2431613663643861642d376265392d343762622d613533642d306463363962366134643966120b71713330373939303538382207424954434f494e2a0f6d2f3439272f30272f30272f302f303209736563703235366b313a074d41494e4e45544206503257504b484ac8010a197472616e73616374696f6e2e4274634b696e5478496e70757412aa010a7d0a4066646461616535663763346565323135343135333361636163653934376162363464626434663061383932353864613763333636643339343064373663383661100018e38a032222334d465a673136634b79547047527054547947746a4e594c63337a734a78764a61352a0f6d2f3439272f30272f30272f302f3012223351657271594e5143644854357a504545314a3532673354376d5971714e7362503618c0843d208b1f").unwrap();
        let action = TcxAction::decode(bytes.as_slice()).unwrap();
        dbg!(&action);
        let param = SignParam::decode(action.param.unwrap().value.as_slice()).unwrap();
        let input = OmniTxInput::decode(param.input.unwrap().value.as_slice()).unwrap();

        let _wallet = import_default_wallet();
        dbg!(&input);
        unsafe {
            call_tcx_api(CString::new(bytes.to_hex()).unwrap().as_ptr());
        }
        assert!(true);
    });
}
