use thiserror::Error;

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum ImkeyError {
    #[error("imkey_tsm_device_authenticity_check_fail")]
    ImkeyTsmDeviceAuthenticityCheckFail,
    #[error("imkey_tsm_device_not_activated")]
    ImkeyTsmDeviceNotActivated,
    #[error("imkey_tsm_device_illegal")]
    ImkeyTsmDeviceIllegal,
    #[error("imkey_tsm_device_stop_using")]
    ImkeyTsmDeviceStopUsing,
    #[error("imkey_tsm_server_error")]
    ImkeyTsmServerError,
    #[error("imkey_se_cert_invalid")]
    ImkeySeCertInvalid,
    #[error("imkey_tsm_device_update_check_fail")]
    ImkeyTsmDeviceUpdateCheckFail,
    #[error("imkey_tsm_device_active_fail")]
    ImkeyTsmDeviceActiveFail,
    #[error("imkey_tsm_receipt_check_fail")]
    ImkeyTsmReceiptCheckFail,
    #[error("imkey_tsm_app_download_fail")]
    ImkeyTsmAppDownloadFail,
    #[error("imkey_tsm_app_update_fail")]
    ImkeyTsmAppUpdateFail,
    #[error("imkey_tsm_app_delete_fail")]
    ImkeyTsmAppDeleteFail,
    #[error("imkey_tsm_oce_cert_check_fail")]
    ImkeyTsmOceCertCheckFail,
    #[error("imkey_tsm_cos_info_no_conf")]
    ImkeyTsmCosInfoNoConf,
    #[error("imkey_tsm_cos_upgrade_fail")]
    ImkeyTsmCosUpgradeFail,
    #[error("imkey_tsm_upload_cos_version_is_null")]
    ImkeyTsmUploadCosVersionIsNull,
    #[error("imkey_tsm_switch_bl_status_fail")]
    ImkeyTsmSwitchBlStatusFail,
    #[error("imkey_tsm_write_wallet_address_fail")]
    ImkeyTsmWriteWalletAddressFail,
    #[error("imkey_device_reconnect_fail")]
    ImkeyDeviceReconnectFail,
    #[error("imkey_tsm_check_update_fail")]
    ImkeyTsmCosCheckUpdateFail,
    #[error("imkey_auth_code_ciphertext_storage_fail")]
    ImkeyTsmAuthCodeCiphertextStorageFail,
    #[error("imkey_tsm_cos_version_unsupport_applet")]
    ImkeyTsmCosVersionUnsupportApplet,
    #[error("imkey_tsm_device_unsupport_applet")]
    ImkeyTsmDeviceUnsupportApplet,
}

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum BindError {
    #[error("imkey_keyfile_io_error")]
    ImkeyKeyfileIoError,
    #[error("imkey_sdk_illegal_argument")]
    ImkeySdkIllegalArgument,
    #[error("imkey_encrypt_authcode_fail")]
    ImkeyEncryptAuthcodeFail,
    #[error("imkey_save_key_file_fail")]
    ImkeySaveKeyFileFail,
    #[error("imkey_authcode_error")]
    ImkeyAuthcodeError,
    #[error("imkey_invalid_bind_status")]
    ImkeyInvalidBindStatus,
}
