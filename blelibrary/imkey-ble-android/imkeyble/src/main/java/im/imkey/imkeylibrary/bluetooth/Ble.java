package im.imkey.imkeylibrary.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.util.Log;

import com.ftsafe.bluetooth.key.FTBtKeyErrCode;
import com.ftsafe.bluetooth.key.jkey.FTBluetoothDevice;
import com.ftsafe.bluetooth.key.jkey.FTBluetoothJKey;
import com.ftsafe.bluetooth.key.jkey.IFTBluetoothKeyInterface;
import com.ftsafe.bluetooth.key.jkey.IFTConnectEventCallback;
import com.ftsafe.bluetooth.key.jkey.IFTRecvDataEventCallback;
import com.ftsafe.bluetooth.key.jkey.IFTScanCallback;

import java.util.HashMap;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

import im.imkey.imkeylibrary.bluetooth.Callback.ConnectCallback;
import im.imkey.imkeylibrary.bluetooth.Callback.ScanCallback;
import im.imkey.imkeylibrary.common.Constants;
import im.imkey.imkeylibrary.common.Messages;
import im.imkey.imkeylibrary.core.Apdu;
import im.imkey.imkeylibrary.exception.ImkeyException;
import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class Ble {
    private static final String TAG = "Ble";
    private FTBluetoothJKey sFtBluetoothJKey;
    private HashMap<String, FTBluetoothDevice> mMapDevices;
    private Boolean initialized = false;
    private BleDevice connectedDevice;
    private Context mContext;

    public static Ble getInstance() {
        return Ble.Holder.sInstance;
    }

    private static class Holder {
        private static Ble sInstance = new Ble();
    }

    public void initialize(Context context, Locale locale) {
        mContext = context;
        sFtBluetoothJKey = FTBluetoothJKey.getInstance(context);
        LogUtil.d("ftversion：" + sFtBluetoothJKey.ftBTKeyComm_GetLibVersion());
        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_Initialize();

        sFtBluetoothJKey.ftBTKeyComm_SetLibLanguage(locale);

        if (ftBtKeyErrCode != FTBtKeyErrCode.FT_BTKey_SUCCESS) {
            throw new ImkeyException(ErrorCode.toErrorCode(ftBtKeyErrCode).get_desc());
        }
        initialized = true;
    }

    public void finalize() {
        initialized = false;
        sFtBluetoothJKey.ftBTKeyComm_Finalize();
    }

    public void startScan(int timeOut, final ScanCallback scanCallback) {

        if (!initialized) {
            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
        }
        if (timeOut <= 0)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        if (scanCallback == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        mMapDevices = new HashMap<>();
        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_StartScan(IFTBluetoothKeyInterface.FT_COMMTYPE_BT4, timeOut, new IFTScanCallback() {
            @Override
            public void onScanStarted() {
                scanCallback.onScanStarted();
            }

            @Override
            public void onScanDevice(FTBluetoothDevice ftBluetoothDevice) {
                mMapDevices.put(ftBluetoothDevice.getBluetoothDevice().getAddress(), ftBluetoothDevice);
                scanCallback.onScanDevice(toDevice(ftBluetoothDevice));
            }

            @Override
            public void onScanStopped() {
                scanCallback.onScanStopped();
            }
        });
        if (ftBtKeyErrCode != FTBtKeyErrCode.FT_BTKey_SUCCESS)
            scanCallback.onScanFail(ErrorCode.toErrorCode(ftBtKeyErrCode));
    }

    public void stopScan() {
        sFtBluetoothJKey.ftBTKeyComm_StopScan();
    }

    public void connect(final BleDevice bleDevice, int timeOut, final ConnectCallback connectCallback) {

        if (!initialized) {
            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
        }

        if (bleDevice == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        if (timeOut <= 0)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        if (connectCallback == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        FTBluetoothDevice device = new FTBluetoothDevice(bleDevice.getBluetoothDevice(),bleDevice.getDevType(),
            bleDevice.getRadioDevName(),bleDevice.getRadioUUID(),bleDevice.getDevRssi(),bleDevice.getRadioManufacturerData());

        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_Connect(device, timeOut, new IFTConnectEventCallback() {
            @Override
            public void onFTBtConnecting(FTBluetoothDevice ftBluetoothDevice) {
                connectCallback.onConnecting(toDevice(ftBluetoothDevice));
            }

            @Override
            public void onFTBtConnected(FTBluetoothDevice ftBluetoothDevice) {
                connectedDevice = toDevice(ftBluetoothDevice);
                keepConnect();
                connectCallback.onConnected(connectedDevice);
            }

            @Override
            public void onFTBtDisconnected(FTBluetoothDevice ftBluetoothDevice) {
                connectedDevice = null;
                connectCallback.onDisconnected(toDevice(ftBluetoothDevice));
            }

            @Override
            public void onFTBtConnectFail(FTBtKeyErrCode ftBtKeyErrCode) {
                connectedDevice = null;
                connectCallback.onConnectFail(ErrorCode.toErrorCode(ftBtKeyErrCode));
            }
        });
        if (ftBtKeyErrCode != FTBtKeyErrCode.FT_BTKey_SUCCESS)
            connectCallback.onConnectFail(ErrorCode.toErrorCode(ftBtKeyErrCode));
    }

    private BleDevice toDevice(FTBluetoothDevice ftBluetoothDevice) {
        if (ftBluetoothDevice == null)
            return null;
        else
            return new BleDevice(ftBluetoothDevice.getBluetoothDevice(), ftBluetoothDevice.getDevType(), ftBluetoothDevice.getRadioDevName(),
                    ftBluetoothDevice.getRadioUUID(), ftBluetoothDevice.getDevRssi(), ftBluetoothDevice.getRadioManufacturerData());
    }

    public void disconnect(BleDevice bleDevice) {
        if (bleDevice == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        if (!initialized) {
            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
        }

        FTBluetoothDevice device = new FTBluetoothDevice(bleDevice.getBluetoothDevice(),bleDevice.getDevType(),
                bleDevice.getRadioDevName(),bleDevice.getRadioUUID(),bleDevice.getDevRssi(),bleDevice.getRadioManufacturerData());

        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_Disconnect(device);
        if (ftBtKeyErrCode != FTBtKeyErrCode.FT_BTKey_SUCCESS) {
            throw new ImkeyException(ErrorCode.toErrorCode(ftBtKeyErrCode).get_desc());
        }
        connectedDevice = null;

    }


    private String mResponse;//send apdu reponse
    private ErrorCode mErrorCode;//send apdu errorcode
    public String sendApdu(String apdu, int timeOut)  {

        if (connectedDevice == null) {
            throw new ImkeyException(ErrorCode.toErrorCode(FTBtKeyErrCode.FT_BTkey_NOT_CONNECTED).get_desc());
        }

        if (apdu == null || apdu.length() % 2 != 0) {
            Log.e(TAG, "invalide apdu");
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        }

        if (timeOut <= 0) {
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        }

        LogUtil.d("ble  >>>>>> " + apdu);

        mResponse = "";
        mErrorCode = null;
        final CountDownLatch latch = new CountDownLatch(1);
        FTBluetoothDevice device = new FTBluetoothDevice(connectedDevice.getBluetoothDevice(), connectedDevice.getDevType(),
                connectedDevice.getRadioDevName(), connectedDevice.getRadioUUID(), connectedDevice.getDevRssi(), connectedDevice.getRadioManufacturerData());

        byte[] bytes = ByteUtil.hexStringToByteArray(apdu);
        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_SendAndRecvAsync(device, bytes, bytes.length, timeOut, new IFTRecvDataEventCallback() {
            @Override
            public void onRecvData(FTBluetoothDevice ftBluetoothDevice, byte[] bytes, int i) {
                mResponse = ByteUtil.byteArrayToHexString(bytes);
                latch.countDown();
            }

            @Override
            public void onRecvFail(FTBluetoothDevice ftBluetoothDevice, FTBtKeyErrCode ftBtKeyErrCode) {
                mErrorCode = ErrorCode.toErrorCode(ftBtKeyErrCode);
                latch.countDown();
            }
        });
        ErrorCode resultCode = ErrorCode.toErrorCode(ftBtKeyErrCode);
        if (resultCode != ErrorCode.SUCCESS) {// check return error code
            throw new ImkeyException(resultCode.get_desc());
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (null != mErrorCode && mErrorCode != ErrorCode.SUCCESS) {//check callback error code
            throw new ImkeyException(mErrorCode.get_desc());
        }
        LogUtil.d("ble  <<<<<< " + mResponse);
        Apdu.checkImKeyStatus(mResponse);

        return mResponse;
    }

    public String sendApdu(String apdu){
        return sendApdu(apdu,Constants.SENT_APDU_TIMEOUT);
    }

    public void connectDirectly(String address, int timeOut, final ConnectCallback connectCallback) {

        if (!initialized) {
            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
        }
        if (address == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        if (timeOut <= 0)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        if (connectCallback == null)
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);

        FTBtKeyErrCode ftBtKeyErrCode = sFtBluetoothJKey.ftBTKeyComm_ConnectDirectly(
                IFTBluetoothKeyInterface.FT_COMMTYPE_BT4, address, timeOut, new IFTConnectEventCallback() {
                    @Override
                    public void onFTBtConnecting(FTBluetoothDevice ftBluetoothDevice) {
                        connectCallback.onConnecting(toDevice(ftBluetoothDevice));
                    }

                    @Override
                    public void onFTBtConnected(FTBluetoothDevice ftBluetoothDevice) {
                        connectedDevice = toDevice(ftBluetoothDevice);
                        keepConnect();
                        connectCallback.onConnected(connectedDevice);
                    }

                    @Override
                    public void onFTBtDisconnected(FTBluetoothDevice ftBluetoothDevice) {
                        connectedDevice = null;
                        connectCallback.onDisconnected(toDevice(ftBluetoothDevice));
                    }

                    @Override
                    public void onFTBtConnectFail(FTBtKeyErrCode ftBtKeyErrCode) {
                        connectedDevice = null;
                        connectCallback.onConnectFail(ErrorCode.toErrorCode(ftBtKeyErrCode));
                    }
                });
        if (ftBtKeyErrCode != FTBtKeyErrCode.FT_BTKey_SUCCESS)
            connectCallback.onConnectFail(ErrorCode.toErrorCode(ftBtKeyErrCode));
    }

    private void keepConnect(){
        String connect = sendApdu(Constants.APDU_GET_BATTERY_POWER);
        Apdu.checkResponse(connect);
    }

    public Context getContext() {
        return mContext;
    }

    private boolean isBluetoothDeviceConnected(BluetoothDevice device) {
        BluetoothManager bluetoothManager = (BluetoothManager) mContext.getSystemService(Context.BLUETOOTH_SERVICE);
        if (bluetoothManager == null) {
            return false;
        }
        int state = bluetoothManager.getConnectionState(device, BluetoothGatt.GATT);
        return state == BluetoothProfile.STATE_CONNECTED;
    }
}
