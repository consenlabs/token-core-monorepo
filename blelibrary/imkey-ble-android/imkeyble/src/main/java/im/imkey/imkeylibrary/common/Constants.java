package im.imkey.imkeylibrary.common;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import im.imkey.imkeylibrary.BuildConfig;

public class Constants {

    //Timeout period for sending APDUs
    public static final int SENT_APDU_TIMEOUT = 20;
    //Send signature prepare data timeout
    public static final int SEND_SIGN_PRE_APDU_TIMEOUT = 120;

    /**
     * apdu
     */
    // select Issuer Security Domain
    public static final String APDU_SELECT_ISD = "00A4040000";
    // get ram size
    public static final String APDU_GET_RAM_SIZE = "80CB800005DFFF02814600";
    // get seid apdu
    public static final String APDU_GET_SEID = "80CB800005DFFF028101";
    // get S/N apdu
    public static final String APDU_GET_SN = "80CA004400";
    // get cert
    public static final String APDU_GET_CERT = "80CABF2106A6048302151800";
    // get cos version
    public static final String APDU_GET_COS_VERSION = "80CB800005DFFF02800300";
    // 获取电量指令
    public static final String APDU_GET_BATTERY_POWER = "00D6FEED01";
    // 获取电量指令
    public static final String APDU_RESET = "80CB800005DFFE02814700";
    // 获取生命周期
    public static final String APDU_GET_LIFE_TIME = "FFDCFEED00";
    // 获取设备蓝牙广播名称
    public static final String APDU_GET_BLE_NAME = "FFDB465400";
    // 获取设备蓝牙版本
    public static final String APDU_GET_BLE_VERSION = "80CB800005DFFF02810000";

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
}
