package im.imkey.imkeylibrary.bluetooth;

import com.ftsafe.bluetooth.key.FTBtKeyErrCode;

public enum ErrorCode {
    SUCCESS(FTBtKeyErrCode.FT_BTKey_SUCCESS, "imkey_ble_success"), //成功
    OTHER_ERROR(FTBtKeyErrCode.FT_BTkey_OTHER_ERROR, "imkey_ble_other_error"),//蓝牙未知错误
    BT_NOT_SUPPORT(FTBtKeyErrCode.FT_BTkey_BT_NOT_SUPPORT, "imkey_ble_not_support"),//不支持蓝牙
    BLE_NOT_SUPPORT(FTBtKeyErrCode.FT_BTkey_BLE_NOT_SUPPORT, "imkey_ble_not_support"),//不支持蓝蓝牙
    LOCATION_UNAUTHORIZE(FTBtKeyErrCode.FT_BTkey_LOCATION_UNAUTHORIZE, "imkey_ble_location_unauthorize"),//您的定位服务未开启，安卓 6.0 系统使用蓝牙需要 开启位置服务
    BT_NOT_ENABLED(FTBtKeyErrCode.FT_BTkey_BT_NOT_ENABLED, "imkey_ble_not_enabled"), //未开启蓝牙
    ENABLE_BT_FAIL(FTBtKeyErrCode.FT_BTKey_ENABLE_BT_FAIL, "imkey_ble_enable_bt_fail"),//开启蓝牙失败
    FIND_DEVICE_FAILED(FTBtKeyErrCode.FT_BTkey_FIND_DEVICE_FAILED, "imkey_ble_find_device_failed"),//未发现设备
    BOND_FAILED(FTBtKeyErrCode.FT_BTkey_BOND_FAILED, "imkey_ble_bond_failed"),//配对失败
    CONNECT_FAILED(FTBtKeyErrCode.FT_BTkey_CONNECT_FAILED, "imkey_ble_connect_failed"),//连接失败
    CONNECT_TIMEOUT(FTBtKeyErrCode.FT_BTkey_CONNECT_TIMEOUT, "imkey_ble_connect_timeout"), //连接超时
    ALREADY_CONNECTED(FTBtKeyErrCode.FT_BTKey_ALREADY_CONNECTED, "imkey_ble_already_connected"),//已存在连接
    CONNECTION_BROKEN(FTBtKeyErrCode.FT_BTkey_CONNECTION_BROKEN, "imkey_ble_connection_broken"),//连接断开
    NOT_CONNECTED(FTBtKeyErrCode.FT_BTkey_NOT_CONNECTED, "imkey_ble_not_connected"),//未连接
    PARA_ERR(FTBtKeyErrCode.FT_BTkey_PARA_ERR, "imkey_ble_illegal_argument"),//参数错误
    SEND_DATA_FAILED(FTBtKeyErrCode.FT_BTkey_SEND_DATA_FAILED, "imkey_ble_send_data_failed"),//数据发送失败
    RECV_BUF_SMALL(FTBtKeyErrCode.FT_BTKey_RECV_BUF_SMALL, "imkey_ble_recv_buf_small"),//接收数据的缓存太小
    RECV_DATA_ERR(FTBtKeyErrCode.FT_BTkey_RECV_DATA_ERR, "imkey_ble_recv_data_err"),//接收到的数据出错，此处指协议上的错误
    RECV_DATA_TIMEOUT(FTBtKeyErrCode.FT_BTkey_RECV_DATA_TIMEOUT, "imkey_ble_recv_data_timeout"),//接收超时(在指定的时间内未收到数据或收到的数据不完整)
    CONCURRENT_EXCEPTION(FTBtKeyErrCode.FT_BTkey_CONCURRENT_EXCEPTION, "imkey_ble_concurrent_exception"),//并发异常
    MATCH_UUID_FAIL(FTBtKeyErrCode.FT_BTkey_MATCH_UUID_FAIL, "imkey_ble_match_uuid_fail");//UUID 匹配失败


    FTBtKeyErrCode _ftBtKeyErrCode;
    String _desc;

    public String get_desc() {
        return _desc;
    }

    ErrorCode(FTBtKeyErrCode ftBtKeyErrCode, String desc) {
        this._ftBtKeyErrCode = ftBtKeyErrCode;
        this._desc = desc;
    }

    public static ErrorCode toErrorCode(FTBtKeyErrCode ftBtKeyErrCode) {
        for (ErrorCode errorCode : values()) {
            if (ftBtKeyErrCode == errorCode._ftBtKeyErrCode) {
                return errorCode;
            }
        }
        return OTHER_ERROR;
    }
}
