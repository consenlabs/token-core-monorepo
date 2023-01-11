package com.mk.imkeylibrary.common;

public class Constants {

    //Timeout period for sending APDUs
    public static final int SENT_APDU_TIMEOUT = 20;
    //Send signature prepare data timeout
    public static final int SEND_SIGN_PRE_APDU_TIMEOUT = 120;


    public static final String APDU_GET_BATTERY_POWER = "00D6FEED01";

    /**
     * apdu response
     */
    public static final String APDU_RSP_SUCCESS = "9000";
    public static final String APDU_RSP_USER_NOT_CONFIRMED = "6940";
    public static final String APDU_CONDITIONS_NOT_SATISFIED = "6985";
    public static final String APDU_RSP_APPLET_NOT_EXIST = "6A82";
    public static final String APDU_RSP_INCORRECT_P1P2 = "6A86";
    public static final String APDU_RSP_CLA_NOT_SUPPORTED = "6E00";
    public static final String APDU_RSP_APPLET_WRONG_DATA = "6A80";
    public static final String APDU_RSP_WRONG_LENGTH = "6700";
    public static final String APDU_RSP_SIGNATURE_VERIFY_FAILED = "6942";
    public static final String APDU_RSP_FUNCTION_NOT_SUPPORTED = "6D00";
    public static final String APDU_RSP_EXCEEDED_MAX_UTXO_NUMBER = "6941";

    public static final String APDU_RSP_WALLET_NOT_CREATED = "F000";
    public static final String APDU_RSP_IN_MENU_PAGE = "F080";
    public static final String APDU_RSP_PIN_NOT_VERIFIED= "F081";
    public static final String APDU_BLUETOOTH_CHANNEL_ERROR= "6F01";

    public static final String MAINNET = "MAINNET";
    public static final String TESTNET = "TESTNET";
}
