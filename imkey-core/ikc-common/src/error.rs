#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum CommonError {
    #[fail(display = "imkey_path_illegal")]
    ImkeyPathIllegal,
}

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum ApduError {
    #[fail(display = "imkey_user_not_confirmed")]
    ImkeyUserNotConfirmed,
    #[fail(display = "imkey_conditions_not_satisfied")]
    ImkeyConditionsNotSatisfied,
    #[fail(display = "imkey_command_format_error")]
    ImkeyCommandFormatError,
    #[fail(display = "imkey_command_data_error")]
    ImkeyCommandDataError,
    #[fail(display = "imkey_applet_not_exist")]
    ImkeyAppletNotExist,
    #[fail(display = "imkey_apdu_wrong_length")]
    ImkeyApduWrongLength,
    #[fail(display = "imkey_signature_verify_fail")]
    ImkeySignatureVerifyFail,
    #[fail(display = "imkey_bluetooth_channel_error")]
    ImkeyBluetoothChannelError,
    #[fail(display = "imkey_applet_function_not_supported")]
    ImkeyAppletFunctionNotSupported,
    #[fail(display = "imkey_exceeded_max_utxo_number")]
    ImkeyExceededMaxUtxoNumber,
    #[fail(display = "imkey_command_execute_fail")]
    ImkeyCommandExecuteFail,
    #[fail(display = "imkey_wallet_not_created")]
    ImkeyWalletNotCreated,
    #[fail(display = "imkey_in_menu_page")]
    ImkeyInMenuPage,
    #[fail(display = "imkey_pin_not_verified")]
    ImkeyPinNotVerified,
}

#[derive(Fail, Debug, PartialOrd, PartialEq)]
pub enum CoinError {
    #[fail(display = "imkey_exceeded_max_utxo_number")]
    ImkeyExceededMaxUtxoNumber,
    #[fail(display = "imkey_address_mismatch_with_path")]
    ImkeyAddressMismatchWithPath,
    #[fail(display = "imkey_signature_verify_fail")]
    ImkeySignatureVerifyFail,
    #[fail(display = "imkey_insufficient_funds")]
    ImkeyInsufficientFunds,
    #[fail(display = "imkey_sdk_illegal_argument")]
    ImkeySdkIllegalArgument,
    #[fail(display = "imkey_amount_less_than_minimum")]
    ImkeyAmountLessThanMinimum,
    #[fail(display = "imkey_path_illegal")]
    ImkeyPathIllegal,
    #[fail(display = "get_xpub_error")]
    GetXpubError,
    #[fail(display = "address_type_mismatch")]
    AddressTypeMismatch,
    #[fail(display = "invalid_address")]
    InvalidAddress,
    #[fail(display = "invalid_number")]
    InvalidNumber,
    #[fail(display = "invalid_param")]
    InvalidParam,
    #[fail(display = "invalid_format")]
    InvalidFormat,
    #[fail(display = "bch_convert_to_legacy_address_failed")]
    ConvertToLegacyAddressFailed,
    #[fail(display = "bch_convert_to_cash_address_failed")]
    ConvertToCashAddressFailed,
    #[fail(display = "construct_bch_address_failed")]
    ConstructBchAddressFailed,
    #[fail(display = "the bech32 payload was empty")]
    EmptyBech32Payload,
    #[fail(display = "invalid witness script version")]
    InvalidWitnessVersion,
    #[fail(display = "the witness program must be between 2 and 40 bytes in length")]
    InvalidWitnessProgramLength,
    #[fail(display = "a v0 witness program must be either of length 20 or 32 bytes")]
    InvalidSegwitV0ProgramLength,
    #[fail(display = "invalid script version")]
    InvalidVersion,
    #[fail(display = "invalid addr length")]
    InvalidAddrLength,
}
