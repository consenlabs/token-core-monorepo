#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum ImkeyError {
    #[fail(display = "imkey_tsm_device_authenticity_check_fail")]
    ImkeyTsmDeviceAuthenticityCheckFail,
    #[fail(display = "imkey_tsm_device_not_activated")]
    ImkeyTsmDeviceNotActivated,
    #[fail(display = "imkey_tsm_device_illegal")]
    ImkeyTsmDeviceIllegal,
    #[fail(display = "imkey_tsm_device_stop_using")]
    ImkeyTsmDeviceStopUsing,
    #[fail(display = "imkey_tsm_server_error")]
    ImkeyTsmServerError,
    #[fail(display = "imkey_se_cert_invalid")]
    ImkeySeCertInvalid,
    #[fail(display = "imkey_tsm_device_update_check_fail")]
    ImkeyTsmDeviceUpdateCheckFail,
    #[fail(display = "imkey_tsm_device_active_fail")]
    ImkeyTsmDeviceActiveFail,
    #[fail(display = "imkey_tsm_receipt_check_fail")]
    ImkeyTsmReceiptCheckFail,
    #[fail(display = "imkey_tsm_app_download_fail")]
    ImkeyTsmAppDownloadFail,
    #[fail(display = "imkey_tsm_app_update_fail")]
    ImkeyTsmAppUpdateFail,
    #[fail(display = "imkey_tsm_app_delete_fail")]
    ImkeyTsmAppDeleteFail,
    #[fail(display = "imkey_tsm_oce_cert_check_fail")]
    ImkeyTsmOceCertCheckFail,
    #[fail(display = "imkey_tsm_cos_info_no_conf")]
    ImkeyTsmCosInfoNoConf,
    #[fail(display = "imkey_tsm_cos_upgrade_fail")]
    ImkeyTsmCosUpgradeFail,
    #[fail(display = "imkey_tsm_upload_cos_version_is_null")]
    ImkeyTsmUploadCosVersionIsNull,
    #[fail(display = "imkey_tsm_switch_bl_status_fail")]
    ImkeyTsmSwitchBlStatusFail,
    #[fail(display = "imkey_tsm_write_wallet_address_fail")]
    ImkeyTsmWriteWalletAddressFail,
    #[fail(display = "imkey_device_reconnect_fail")]
    ImkeyDeviceReconnectFail,
    #[fail(display = "imkey_tsm_check_update_fail")]
    ImkeyTsmCosCheckUpdateFail,
    #[fail(display = "imkey_auth_code_ciphertext_storage_fail")]
    ImkeyTsmAuthCodeCiphertextStorageFail,
    #[fail(display = "imkey_tsm_cos_version_unsupport_applet")]
    ImkeyTsmCosVersionUnsupport_applet,
    #[fail(display = "imkey_tsm_device_unsupport_applet")]
    ImkeyTsmDeviceUnsupport_applet,
}

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum BindError {
    #[fail(display = "imkey_keyfile_io_error")]
    ImkeyKeyfileIoError,
    #[fail(display = "imkey_sdk_illegal_argument")]
    ImkeySdkIllegalArgument,
    #[fail(display = "imkey_encrypt_authcode_fail")]
    ImkeyEncryptAuthcodeFail,
    #[fail(display = "imkey_save_key_file_fail")]
    ImkeySaveKeyFileFail,
    #[fail(display = "imkey_authcode_error")]
    ImkeyAuthcodeError,
}
