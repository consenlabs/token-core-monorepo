package im.imkey.imkeylibrary.bluetooth.Callback;

import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;

public interface ScanCallback{
    void onScanStarted();

    void onScanDevice(BleDevice bleDevice);

    void onScanStopped();

    void onScanFail(ErrorCode errorCode);
}
