pub const VERSION: &str = "2.10.3";
pub const URL: &str = "https://imkey.online:1000/imkey";
// pub const URL: &str = "https://imkeyserver.com:10444/imkey";

pub const TSM_ACTION_SE_SECURE_CHECK: &str = "/seSecureCheck";
pub const TSM_ACTION_APP_DOWNLOAD: &str = "/appDownload";
pub const TSM_ACTION_APP_UPDATE: &str = "/appUpdate";
pub const TSM_ACTION_APP_DELETE: &str = "/appDelete";
pub const TSM_ACTION_SE_ACTIVATE: &str = "/seActivate";
pub const TSM_ACTION_SE_QUERY: &str = "/seInfoQuery";
pub const TSM_ACTION_AUTHCODE_STORAGE: &str = "/authCodeStorage";
pub const TSM_ACTION_DEVICE_CERT_CHECK: &str = "/deviceCertCheck";
pub const TSM_ACTION_COS_UPGRADE: &str = "/seCosUpdate";
pub const TSM_ACTION_COS_CHECK_UPDATE: &str = "/cosCheckUpdate";

//apud related constant
pub const LC_MAX: u32 = 245;

pub const ETH_AID: &str = "695F657468";
pub const EOS_AID: &str = "695F656F73";
pub const BTC_AID: &str = "695F627463";
pub const COSMOS_AID: &str = "695F636F736D6F73";
pub const FILECOIN_AID: &str = "695F6B315F66696C";
pub const IMK_AID: &str = "695F696D6B";
pub const POLKADOT_AID: &str = "695F65645F646F74";
pub const KUSAMA_AID: &str = "695F65645F6B736D";
pub const TRON_AID: &str = "695F6B315F747278";
pub const NERVOS_AID: &str = "695F6B315F636B62";
pub const TEZOS_AID: &str = "695F65645F78747A";
pub const BCH_AID: &str = "695F626368";
pub const LTC_AID: &str = "695F6C7463";

pub const BL_AID: &str = "D0426F6F746C6F61646572";

//path
pub const COSMOS_PATH: &str = "m/44'/118'/0'/0/0";
pub const EOS_PATH: &str = "m/44'/194'/0'/0/0";
pub const ETH_PATH: &str = "m/44'/60'/0'/0/0";
pub const FILECOIN_PATH: &str = "m/44'/461'/0/0/0";
pub const NERVOS_PATH: &str = "m/44'/309'/0'/0/0";
pub const POLKADOT_PATH: &str = "m/44'/354'/0'/0'/0'";
pub const KUSAMA_PATH: &str = "m/44'/434'/0'/0'/0'";
pub const TRON_PATH: &str = "m/44'/195'/0'/0/0";

pub const MAX_UTXO_NUMBER: usize = 252;
pub const EACH_ROUND_NUMBER: usize = 5;
pub const DUST_THRESHOLD: i64 = 2730;
pub const MIN_NONDUST_OUTPUT: i64 = 546;
// max op return size
pub const MAX_OPRETURN_SIZE: usize = 80;
pub const BTC_FORK_DUST: i64 = 546;

// imkey device status
pub const IMKEY_DEV_STATUS_INACTIVATED: &str = "inactivated";
pub const IMKEY_DEV_STATUS_LATEST: &str = "latest";

//device bind status
pub const BIND_STATUS_UNBOUND: &str = "00";
pub const BIND_STATUS_BOUND_THIS: &str = "55";
pub const BIND_STATUS_BOUND_OTHER: &str = "AA";
pub const BIND_RESULT_SUCCESS: &str = "5A";
pub const BIND_RESULT_ERROR: &str = "A5";

// tsm return code
pub const TSM_RETURN_CODE_SUCCESS: &str = "000000";
pub const TSM_RETURNCODE_DEV_INACTIVATED: &str = "BSE0007";
pub const TSM_RETURNCODE_DEVICE_ILLEGAL: &str = "BSE0017";
pub const TSM_RETURNCODE_DEVICE_STOP_USING: &str = "BSE0019";
pub const TSM_RETURNCODE_SE_QUERY_FAIL: &str = "BSE0018";
pub const TSM_RETURNCODE_DEVICE_ACTIVE_FAIL: &str = "BSE0015";
pub const TSM_RETURNCODE_SEID_ILLEGAL: &str = "BSE0008";
pub const TSM_RETURNCODE_DEVICE_CHECK_FAIL: &str = "BSE0009";
pub const TSM_RETURNCODE_RECEIPT_CHECK_FAIL: &str = "BSE0012";
pub const TSM_RETURNCODE_OCE_CERT_CHECK_FAIL: &str = "BSE0010";
pub const TSM_RETURNCODE_APP_DOWNLOAD_FAIL: &str = "BAPP0006";
pub const TSM_RETURNCODE_APP_UPDATE_FAIL: &str = "BAPP0008";
pub const TSM_RETURNCODE_APP_DELETE_FAIL: &str = "BAPP0011";
pub const TSM_RETURNCODE_COS_INFO_NO_CONF: &str = "BCOS0001";
pub const TSM_RETURNCODE_COS_UPGRADE_FAIL: &str = "BCOS0003";
pub const TSM_RETURNCODE_UPLOAD_COS_VERSION_IS_NULL: &str = "BCOS0004";
pub const TSM_RETURNCODE_SWITCH_BL_STATUS_FAIL: &str = "BCOS0005";
pub const TSM_RETURNCODE_WRITE_WALLET_ADDRESS_FAIL: &str = "BCOS0006";
pub const TSM_RETURNCODE_COS_CHECK_UPDATE_FAIL: &str = "BCOS0007";
pub const TSM_RETURNCODE_AUTH_CODE_HANDLE_FAIL: &str = "BDEVICE001";
pub const TSM_RETURNCODE_COS_VERSION_UNSUPPORT_APPLET: &str = "BAPP0014";
pub const TSM_RETURNCODE_DEVICE_UNSUPPORT_APPLET: &str = "BAPP0015";

//tsm end flag
pub const TSM_END_FLAG: &str = "end";

pub const APDU_RSP_SUCCESS: &str = "9000";
pub const APDU_RSP_USER_NOT_CONFIRMED: &str = "6940";
pub const APDU_CONDITIONS_NOT_SATISFIED: &str = "6985";
pub const APDU_RSP_APPLET_NOT_EXIST: &str = "6A82";
pub const APDU_RSP_INCORRECT_P1P2: &str = "6A86";
pub const APDU_RSP_CLA_NOT_SUPPORTED: &str = "6E00";
pub const APDU_RSP_APPLET_WRONG_DATA: &str = "6A80";
pub const APDU_RSP_WRONG_LENGTH: &str = "6700";
pub const APDU_RSP_SIGNATURE_VERIFY_FAILED: &str = "6942";
pub const APDU_RSP_FUNCTION_NOT_SUPPORTED: &str = "6D00";
pub const APDU_RSP_EXCEEDED_MAX_UTXO_NUMBER: &str = "6941";
pub const APDU_RSP_WALLET_NOT_CREATED: &str = "F000";
pub const APDU_RSP_IN_MENU_PAGE: &str = "F080";
pub const APDU_RSP_PIN_NOT_VERIFIED: &str = "F081";
pub const APDU_BLUETOOTH_CHANNEL_ERROR: &str = "6F01";
pub const APDU_RSP_SWITCH_BL_STATUS_SUCCESS: &str = "905A";

pub const TIMEOUT_LONG: i32 = 120;
pub const DEVICE_MODEL_NAME: &str = "imKey Pro";
//network connect
pub const NETWORK_CONN_TIMEOUT: u16 = 30;
pub const NETWORK_WRITE_TIMEOUT: u16 = 30;
pub const NETWORK_READ_TIMEOUT: u16 = 30;

pub const ETH_TRANSACTION_TYPE_LEGACY: &str = "00";
pub const ETH_TRANSACTION_TYPE_EIP2718: &str = "01";
pub const ETH_TRANSACTION_TYPE_EIP1559: &str = "02";

pub const ETH_MAX_SUPPORT_PAYMENT_LEN: usize = 255;
