package com.mk.imkeydemo.keycore;


import com.mk.imkeydemo.BuildConfig;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class Constants {

    //sdk version
    public static final String version = "1.2.00";

    //Timeout period for sending APDUs
    public static final int SENT_APDU_TIMEOUT = 20;
    //Send signature prepare data timeout
    public static final int SEND_SIGN_PRE_APDU_TIMEOUT = 120;

    // TSM 处理成功的返回码
    public static final String TSM_RETURNCODE_SUCCESS = "000000";
    public static final String TSM_RETURNCODE_DEV_INACTIVATED = "BSE0007";
    public static final String TSM_RETURNCODE_DEVICE_ILLEGAL = "BSE0017";
    public static final String TSM_RETURNCODE_DEVICE_STOP_USING = "BSE0019";
    public static final String TSM_RETURNCODE_SE_QUERY_FAIL = "BSE0018";

    public static final String TSM_RETURNCODE_DEVICE_ACTIVE_FAIL = "BSE0015";
    public static final String TSM_RETURNCODE_SEID_ILLEGAL = "BSE0008";

    public static final String TSM_RETURNCODE_DEVICE_CHECK_FAIL = "BSE0009";
    public static final String TSM_RETURNCODE_RECEIPT_CHECK_FAIL = "BSE0012";
    public static final String TSM_RETURNCODE_OCE_CERT_CHECK_FAIL = "BSE0010";

    public static final String TSM_RETURNCODE_APP_DOWNLOAD_FAIL = "BAPP0006";

    public static final String TSM_RETURNCODE_APP_UPDATE_FAIL = "BAPP0008";

    public static final String TSM_RETURNCODE_APP_DELETE_FAIL = "BAPP0011";

    // imKey device status
    public static final String IMKEY_DEV_STATUS_INACTIVATED = "inactivated";
    public static final String IMKEY_DEV_STATUS_OUTDATED = "outdated";
    public static final String IMKEY_DEV_STATUS_LATEST = "latest";



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

    private static final String TEST_HOST = "https://imkeyserver.com:10443/imkey/";
    private static final String TEST_SSL_CERT = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100880430F1269DC7388CF1E525A1FB400402D91880CEC25CCAA0F50142C6B45A9845483CCEF6416FE5807F76A128125AE26190C30C5C8BD105E5E25953B41234917CABAAD13DB9ECD94B4B52D76BC2B059BD7A304A6E72573BB46DE642F2F74E2FFA378E3D9FC9C02B8FF1A50823B1342EDE39193E98F00EC0B851BF1F1ADA83FF6BB6DCCC5080124FFC289BB2188ED33C05743C7F7485533C961E20F83357AC7E5C5E3A34557923BA9F5ECDF236714900455E9EA29E966D88F6802227A2CD9305A092D5A9EC4852FE6F07A75FF7A5E6C0ED6B16F6DB5C08ED036D4C07411360CA5DC58079ADB4AA5C2972F05A5C69EC6420267ACA44D89AF4ECFE490939C765770203010001";

    private static final String PRODUCT_HOST = "https://imkey.online:1000/imkey/";
    private static final String PRODUCT_SSL_CERT = "30820122300D06092A864886F70D01010105000382010F003082010A028201010088BFDFBE85067CD720583FA3F5659BBA629A2335A924F618001DF1B9B89DB769B1C75273493D51CDAD6588441E015226CAAB0D1319BFEAB9E257E6FE6C8227640DA2A5FCCC58963269C908EEEEEB0B7D14E312D15A104E81BC45D1112DCB978C3CA0D483FFB405D6CAC10909733B6B0A8D369B24611E4C284D05077901F36365B407DC3CB29C7B42664A8958063D93E87D405BEE692EDA4068A841D4EE12D7FC57494B24EE72537DAC29DCDCCD721D4AA8C1306D6613B8E04861844DB49DE10A140A7EB8C4D0351CAF5D76D44AADCC5C37E7504A24E31E92F6F3CBC133BF4EFFA889A14D6F1A684A9B471BC5B040F3C04D163158970EED5AE9A011F2A3DDB0810203010001";

    public static final String HOST_HTTPS = BuildConfig.DEBUG ? TEST_HOST : PRODUCT_HOST;
    public static final String SSL_CERT_PUBKEY = BuildConfig.DEBUG ? TEST_SSL_CERT : PRODUCT_SSL_CERT;

    //Timeout period for https
    public static final int HTTP_TIMEOUT = 10000;


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

    //The value S in signatures must be between 0x1 and 0x7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0 (inclusive). If S is too high, simply replace it by S' = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 - S.
    public static final BigInteger HALF_CURVE_ORDER = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",16);
    public static final BigInteger CURVE_N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);

    //  network
    public static final String MAINNET = "MAINNET";
    public static final String TESTNET = "TESTNET";

    // Battery is charging sign
    public static final String BATTERY_CHARGING_SIGN = "FF";


    // 设备初始化 80
    public static final String LIFE_TIME_DEVICE_INITED = "life_time_device_inited";
    // 已激活 89
    public static final String LIFE_TIME_DEVICE_ACTIVATED = "life_time_device_activated";
    // pin未设置 81
    public static final String LIFE_TIME_UNSET_PIN = "life_time_unset_pin";
    // 钱包unready 83
    public static final String LIFE_TIME_WALLET_UNREADY = "life_time_wallet_unready";
    // 钱包创建中 84
    public static final String LIFE_TIME_WALLET_CREATTING = "life_time_wallet_creatting";
    // 钱包恢复中 85
    public static final String LIFE_TIME_WALLET_RECOVERING = "life_time_wallet_recovering";
    // 钱包创建完成 86
    public static final String LIFE_TIME_WALLET_READY = "life_time_wallet_ready";
    // 未知
    public static final String LIFE_TIME_UNKNOWN = "life_time_unknown";

    //设备绑定状态
    public static final String BIND_STATUS_UNBOUND = "00";
    public static final String BIND_STATUS_BOUND_THIS = "55";
    public static final String BIND_STATUS_BOUND_OTHER = "AA";

    // bindcheck status
    public static Map<String, String> bindcheckStatusMap = new HashMap<String, String>();
    static {
        bindcheckStatusMap.put("00", "unbound");
        bindcheckStatusMap.put("55", "bound_this");
        bindcheckStatusMap.put("AA", "bound_other");
    }

    // bindcheck status
    public static Map<String, String> identityVerifyStatusMap = new HashMap<String, String>();
    static {
        identityVerifyStatusMap.put("5A", "success");
        identityVerifyStatusMap.put("A5", "authcode_error");
    }

    // authcode encrypt public key
    public final static String AUTHCODE_ENC_PUB_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxmJ6bwSFsz3cHKfgYsZO\n" +
            "iEETO5JGpB9A0HZ7rkTqsu9FPQCP+we42f380hiCSH7MTakzyX5JQkKto84CxaBR\n" +
            "iapJQQ53GmboEA5Dyxr2zGELWe5OuyNv84xirXsdEd+9TgVNGeM0k5GjH16JynIS\n" +
            "krc4ApV0XYlozFwtIjrGdQuwrKJ3c2h+nNdgZeR/QvSuAFRZvOV0a9dgZGpb0Rm6\n" +
            "NGmpNfSOuJjLq3LLOUw/7J5BY16ulUEHoXrHuMYyHY8XVa05FanSOY2yaKP2Qs7p\n" +
            "y+n4Ls1a1k6+3d5mYB3CuJHi/t33La9if6j6FvfGQNtmG+Fdy0J02VdtmNvrIMJT\n" +
            "CQIDAQAB";

    //each round number
    public final static int EACH_ROUND_NUMBER = 5;

    // max utxo number
    public static final int MAX_UTXO_NUMBER = 252;

}
