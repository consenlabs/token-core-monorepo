package im.imkey.imkeylibrary.bluetooth.Callback;

import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;

public interface ConnectCallback {
    void onConnecting(BleDevice bleDevice);

    void onConnected(BleDevice bleDevice);

    void onDisconnected(BleDevice bleDevice);

    void onConnectFail(ErrorCode errorCode);
}
