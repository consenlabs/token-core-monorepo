use api::sign_param::Key;
use error_handling::Result;
use serial_test::serial;
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
    SignAuthenticationMessageResult, SignHashesParam, SignHashesResult, SignParam, TcxAction,
    WalletKeyParam,
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

pub fn _to_c_char(str: &str) -> *const c_char {
    CString::new(str).unwrap().into_raw()
}

pub fn _to_str(json_str: *const c_char) -> &'static str {
    let json_c_str = unsafe { CStr::from_ptr(json_str) };
    json_c_str.to_str().unwrap()
}

pub fn setup() {
    let p = Path::new("/tmp/imtoken/wallets");
    if !p.exists() {
        fs::create_dir_all(p).expect("shoud create filedir");
    }

    init_token_core_x("/tmp/imtoken");
}

pub fn teardown() {
    fs::remove_dir_all("/tmp/imtoken").expect("remove test directory");
}

pub fn run_test<T>(test: T) -> ()
where
    T: FnOnce() -> () + panic::UnwindSafe,
{
    setup();
    let result = panic::catch_unwind(|| test());
    teardown();
    assert!(result.is_ok())
}

pub fn import_default_wallet() -> KeystoreResult {
    let param = ImportMnemonicParam {
        mnemonic: TEST_MNEMONIC.to_string(),
        password: TEST_PASSWORD.to_string(),
        network: "TESTNET".to_string(),
        name: "test-wallet".to_string(),
        password_hint: "imtoken".to_string(),
        overwrite: true,
    };
    let ret = import_mnemonic(&encode_message(param).unwrap()).unwrap();
    KeystoreResult::decode(ret.as_slice()).unwrap()
}

pub fn import_default_pk_store() -> ImportPrivateKeyResult {
    let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
        private_key: "L2hfzPyVC1jWH7n2QLTe7tVTb6btg9smp5UVzhEBxLYaSFF7sCZB".to_string(),
        password: TEST_PASSWORD.to_string(),
        name: "import_default_pk_store".to_string(),
        password_hint: "".to_string(),
        network: "".to_string(),
        overwrite: true,
    };

    let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
    ImportPrivateKeyResult::decode(ret.as_slice()).unwrap()
}

pub fn import_filecoin_pk_store() -> KeystoreResult {
    let param: ImportPrivateKeyParam = ImportPrivateKeyParam {
        private_key: "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a".to_string(),
        password: TEST_PASSWORD.to_string(),
        name: "import_filecoin_pk_store".to_string(),
        password_hint: "".to_string(),
        network: "".to_string(),
        overwrite: true,
    };

    let ret = import_private_key(&encode_message(param).unwrap()).unwrap();
    KeystoreResult::decode(ret.as_slice()).unwrap()
}

pub fn import_and_derive(derivation: Derivation) -> (KeystoreResult, DeriveAccountsResult) {
    let wallet = import_default_wallet();

    let param = DeriveAccountsParam {
        id: wallet.id.to_string(),
        key: Some(tcx::api::derive_accounts_param::Key::Password(
            TEST_PASSWORD.to_owned(),
        )),
        derivations: vec![derivation],
    };

    let ret = call_api("derive_accounts", param).unwrap();
    let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

    (wallet, accounts)
}

pub fn import_pk_and_derive(
    derivation: Derivation,
) -> (ImportPrivateKeyResult, DeriveAccountsResult) {
    let wallet = import_default_pk_store();

    let param = DeriveAccountsParam {
        id: wallet.id.to_string(),
        key: Some(tcx::api::derive_accounts_param::Key::Password(
            TEST_PASSWORD.to_owned(),
        )),
        derivations: vec![derivation],
    };

    let ret = call_api("derive_accounts", param).unwrap();
    let accounts: DeriveAccountsResult = DeriveAccountsResult::decode(ret.as_slice()).unwrap();

    (wallet, accounts)
}

pub fn call_api(method: &str, msg: impl Message) -> Result<Vec<u8>> {
    let param = TcxAction {
        method: method.to_string(),
        param: Some(::prost_types::Any {
            type_url: "imtoken".to_string(),
            value: encode_message(msg).unwrap(),
        }),
    };
    let _ = unsafe { clear_err() };
    let param_bytes = encode_message(param).unwrap();
    let param_hex = param_bytes.to_hex();
    let ret_hex = unsafe { _to_str(call_tcx_api(_to_c_char(&param_hex))) };
    let err = unsafe { _to_str(get_last_err_message()) };
    if !err.is_empty() {
        let err_bytes = Vec::from_hex(err).unwrap();
        let err_ret: GeneralResult = GeneralResult::decode(err_bytes.as_slice()).unwrap();
        Err(anyhow!("{}", err_ret.error))
    } else {
        Ok(Vec::from_hex(ret_hex).unwrap())
    }
}

pub fn init_token_core_x(file_dir: &str) {
    let param = InitTokenCoreXParam {
        file_dir: file_dir.to_string(),
        xpub_common_key: "B888D25EC8C12BD5043777B1AC49F872".to_string(),
        xpub_common_iv: "9C0C30889CBCC5E01AB5B2BB88715799".to_string(),
        is_debug: true,
    };
    let response = call_api("init_token_core_x", param);
    assert!(response.is_ok());
}

pub fn remove_created_wallet(wid: &str) {
    let full_file_path = format!("{}/{}.json", "/tmp/imtoken/walletsv2", wid);
    let p = Path::new(&full_file_path);
    remove_file(p).expect("should remove file");
}
