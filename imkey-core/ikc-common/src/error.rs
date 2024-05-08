use thiserror::Error;

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum CommonError {
    #[error("imkey_path_illegal")]
    ImkeyPathIllegal,
    #[error("invalid_key_iv_length")]
    InvalidKeyIvLength,
    #[error("invalid_base58")]
    InvalidBase58,
}

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum ApduError {
    #[error("imkey_user_not_confirmed")]
    ImkeyUserNotConfirmed,
    #[error("imkey_conditions_not_satisfied")]
    ImkeyConditionsNotSatisfied,
    #[error("imkey_command_format_error")]
    ImkeyCommandFormatError,
    #[error("imkey_command_data_error")]
    ImkeyCommandDataError,
    #[error("imkey_applet_not_exist")]
    ImkeyAppletNotExist,
    #[error("imkey_apdu_wrong_length")]
    ImkeyApduWrongLength,
    #[error("imkey_signature_verify_fail")]
    ImkeySignatureVerifyFail,
    #[error("imkey_bluetooth_channel_error")]
    ImkeyBluetoothChannelError,
    #[error("imkey_applet_function_not_supported")]
    ImkeyAppletFunctionNotSupported,
    #[error("imkey_exceeded_max_utxo_number")]
    ImkeyExceededMaxUtxoNumber,
    #[error("imkey_command_execute_fail")]
    ImkeyCommandExecuteFail,
    #[error("imkey_wallet_not_created")]
    ImkeyWalletNotCreated,
    #[error("imkey_in_menu_page")]
    ImkeyInMenuPage,
    #[error("imkey_pin_not_verified")]
    ImkeyPinNotVerified,
}

#[derive(Error, Debug, PartialOrd, PartialEq)]
pub enum CoinError {
    #[error("imkey_exceeded_max_utxo_number")]
    ImkeyExceededMaxUtxoNumber,
    #[error("imkey_address_mismatch_with_path")]
    ImkeyAddressMismatchWithPath,
    #[error("imkey_signature_verify_fail")]
    ImkeySignatureVerifyFail,
    #[error("imkey_insufficient_funds")]
    ImkeyInsufficientFunds,
    #[error("imkey_sdk_illegal_argument")]
    ImkeySdkIllegalArgument,
    #[error("imkey_amount_less_than_minimum")]
    ImkeyAmountLessThanMinimum,
    #[error("imkey_path_illegal")]
    ImkeyPathIllegal,
    #[error("get_xpub_error")]
    GetXpubError,
    #[error("address_type_mismatch")]
    AddressTypeMismatch,
    #[error("invalid_address")]
    InvalidAddress,
    #[error("invalid_number")]
    InvalidNumber,
    #[error("invalid_param")]
    InvalidParam,
    #[error("invalid_format")]
    InvalidFormat,
    #[error("bch_convert_to_legacy_address_failed")]
    ConvertToLegacyAddressFailed,
    #[error("bch_convert_to_cash_address_failed")]
    ConvertToCashAddressFailed,
    #[error("construct_bch_address_failed")]
    ConstructBchAddressFailed,
    #[error("the bech32 payload was empty")]
    EmptyBech32Payload,
    #[error("invalid witness script version")]
    InvalidWitnessVersion,
    #[error("the witness program must be between 2 and 40 bytes in length")]
    InvalidWitnessProgramLength,
    #[error("a v0 witness program must be either of length 20 or 32 bytes")]
    InvalidSegwitV0ProgramLength,
    #[error("invalid script version")]
    InvalidVersion,
    #[error("invalid addr length")]
    InvalidAddrLength,
}
