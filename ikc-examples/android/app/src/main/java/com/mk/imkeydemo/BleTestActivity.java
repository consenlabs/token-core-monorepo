package com.mk.imkeydemo;

import android.app.Activity;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.Nullable;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.Callback.ConnectCallback;
import im.imkey.imkeylibrary.bluetooth.Callback.ScanCallback;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;
import im.imkey.imkeylibrary.exception.ImkeyException;
import im.imkey.imkeylibrary.utils.LogUtil;


public class BleTestActivity extends Activity implements AdapterView.OnItemClickListener {
    private static final String TAG = "ble";
    private Context mContext;
    private List<String> deviceInfos;
    private List<BleDevice> devices;
    private List<BleDevice> devices2;
    private ArrayAdapter<String> adapter;
    private BleDevice mDevice;
    private int connectTimes;
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ble);
        mContext = this;
        setFinishOnTouchOutside(true);

        devices = new ArrayList<>();
        devices2 = new ArrayList<>();
        deviceInfos = new ArrayList<>();

    }

    public void onClick(View view) {
//        mTxtInfo.setText(null);
        switch (view.getId()) {

            // test getinstance
            case R.id.btn_getinst_001:
                getinst_001();
                break;
            case R.id.btn_getinst_002:
                getinst_002();
                break;
            case R.id.btn_initialize_001:
                initialize_001();
                break;
            // test start scan
            case R.id.btn_startscan_001:
                initialize_001();
                startscan_001();
                break;
            case R.id.btn_startscan_002:
                startscan_001();
                break;
            case R.id.btn_startscan_003:
                initialize_001();
                finalize_001();
                startscan_001();
                break;
            case R.id.btn_startscan_004:
                initialize_001();
                startscan_001();
                startscan_001();
                break;
            case R.id.btn_startscan_005:
                initialize_001();
                startscan_001();
                stopscan_001();
                startscan_001();
                break;
            case R.id.btn_startscan_006:
                initialize_001();
                startscan_001();
                break;
            case R.id.btn_startscan_007:
                initialize_001();
                startscan_001();
                break;
            case R.id.btn_startscan_008:
                initialize_001();
                startscan_001();
                break;
            case R.id.btn_connect_001:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 10);
                break;
            case R.id.btn_connect_002:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),1);
                    }
                },1000 * 5);
                break;

            case R.id.btn_connect_003:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_004:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_005:
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_006:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        finalize_001();
                        initialize_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_007:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_008:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        startscan_002();
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                connect_001(devices.size() == 0 ? null : devices.get(0),20);
                            }
                        },1000 * 5);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_009:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_010:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_011:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        finalize_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_012:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 5);
                break;
            case R.id.btn_connect_013:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 10);
                break;
            case R.id.btn_connect_014:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                    }
                },1000 * 10);
                break;
            case R.id.btn_connect_015:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                connect_001(devices.size() == 0 ? null : devices.get(0),20);
                            }
                        },1000 * 5);
                    }
                },1000 * 10);
                break;
            case R.id.btn_connect_016:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connectTimes = 10;
                        connect_disconnect();
                    }
                },1000 * 10);
                break;
            case R.id.btn_disconnect_001:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                disconnect_001(devices.size() == 0 ? null : devices.get(0));
                            }
                        },1000 * 5);
                    }
                },1000 * 8);
                break;
            case R.id.btn_disconnect_002:
                initialize_001();
                disconnect_001(null);
                break;
            case R.id.btn_disconnect_003:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                disconnect_001(devices.size() == 0 ? null : devices.get(0));
                                new Handler().postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        disconnect_001(devices.size() == 0 ? null : devices.get(0));
                                    }
                                },1000 * 5);
                            }
                        },1000 * 5);
                    }
                },1000 * 8);
                break;
            case R.id.btn_disconnect_004:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        disconnect_001(devices.size() == 0 ? null : devices.get(0));

                    }
                },1000 * 8);
                break;
            case R.id.btn_disconnect_005:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                finalize_001();
                                disconnect_001(devices.size() == 0 ? null : devices.get(0));
                            }
                        },1000 * 5);
                    }
                },1000 * 8);
                break;
            case R.id.btn_disconnect_006:
                initialize_001();
                startscan_001();
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopscan_001();
                        connect_001(devices.size() == 0 ? null : devices.get(0),20);
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                disconnect_001(devices.size() == 0 ? null : devices.get(0));
                            }
                        },1000 * 15);
                    }
                },1000 * 8);
                break;
            case R.id.btn_stopscan_001:
                initialize_001();
                startscan_001();
                stopscan_001();
                break;
            case R.id.btn_stopscan_002:
                initialize_001();
                stopscan_001();
                break;
            case R.id.btn_stopscan_003:
                stopscan_001();
                break;
            case R.id.btn_stopscan_004:
                initialize_001();
                startscan_001();
                stopscan_001();
                stopscan_001();
                break;
            case R.id.btn_finalize_001:
                initialize_001();
                finalize_001();
                break;
            case R.id.btn_finalize_002:
                finalize_001();
                break;
            case R.id.btn_finalize_003:
                initialize_001();
                finalize_001();
                finalize_001();
                break;
            case R.id.btn_conndirectly_001:
                initialize_001();
                connectDirectly_001("CC:F3:8A:91:97:54",20);
                break;
            default:
                break;
        }
    }


    private void search() {

    }

    /**
     * getInstance test
     */
    private void getinst_001() {
        try {
            Ble.getInstance();
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }

    private void getinst_002() {
        try {
            Ble ble = Ble.getInstance();
            toast(ble.toString());
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }

    private void initialize_001() {
        try {
           Ble.getInstance().initialize(mContext,new Locale("cn"));
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }


    private void startscan_001() {
        devices.clear();
        try {
            Ble.getInstance().startScan(20, new ScanCallback() {
                @Override
                public void onScanStarted() {
                    Log.d(TAG, "scan start...");
                }

                @Override
                public void onScanDevice(BleDevice bleDevice) {
                    devices.add(bleDevice);
                    deviceInfos.add(bleDevice.toString());
                    Log.d(TAG, "Scanned device :" + bleDevice.toString());
                }

                @Override
                public void onScanStopped() {
                    Log.d(TAG, "scan stop");
                }

                @Override
                public void onScanFail(ErrorCode errorCode) {
                    Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
                }
            });
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }

    }

    private void startscan_002() {
        devices2.clear();
        try {
            Ble.getInstance().startScan(20, new ScanCallback() {
                @Override
                public void onScanStarted() {
                    Log.d(TAG, "scan start...");
                }

                @Override
                public void onScanDevice(BleDevice bleDevice) {
                    devices2.add(bleDevice);
                    deviceInfos.add(bleDevice.toString());
                    Log.d(TAG, "Scanned device :" + bleDevice.toString());
                }

                @Override
                public void onScanStopped() {
                    Log.d(TAG, "scan stop");
                }

                @Override
                public void onScanFail(ErrorCode errorCode) {
                    Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
                }
            });
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }

    }

    private void connect_001(BleDevice bleDevice, int timeout) {
        try {
            Ble.getInstance().connect(bleDevice, timeout, new ConnectCallback() {
                @Override
                public void onConnecting(BleDevice bleDevice) {
                    Log.d(TAG, "onConnecting... " + bleDevice.toString());
                }

                @Override
                public void onConnected(BleDevice bleDevice) {
                    mDevice = bleDevice;
                    Log.d(TAG, "onConnected... " + bleDevice.toString());
                    BluetoothManager bm = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
                    int status = bm.getConnectionState(bleDevice.getBluetoothDevice(), BluetoothGatt.GATT);
                    LogUtil.d(status + "");
                }

                @Override
                public void onDisconnected(BleDevice bleDevice) {
                    Log.d(TAG, "onDisconnected... " + bleDevice.toString());
                }

                @Override
                public void onConnectFail(ErrorCode errorCode) {
                    Log.d(TAG, "onConnectFail... " + errorCode.toString() + errorCode.get_desc());
                    Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
                }
            });
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }

    private void connectDirectly_001(String address, int timeout) {

        address = "CC:F3:8A:91:97:54"; // eeui

        try {

            Ble.getInstance().connectDirectly(address, 20, new ConnectCallback() {

                @Override
                public void onConnecting(BleDevice bleDevice) {
                    Log.d(TAG, "onConnecting... " + bleDevice.toString());
                }

                @Override
                public void onConnected(BleDevice bleDevice) {
                    mDevice = bleDevice;
                    Log.d(TAG, "onConnected... " + bleDevice.toString());
                    BluetoothManager bm = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
                    int status = bm.getConnectionState(bleDevice.getBluetoothDevice(), BluetoothGatt.GATT);
                    LogUtil.d(status + "");
                }

                @Override
                public void onDisconnected(BleDevice bleDevice) {
                    Log.d(TAG, "onDisconnected... " + bleDevice.toString());
                }

                @Override
                public void onConnectFail(ErrorCode errorCode) {
                    Log.d(TAG, "onConnectFail... " + errorCode.toString() + errorCode.get_desc());
                    Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
                }
            });
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }

    private void connect_disconnect() {

        connect_001(devices.size() == 0 ? null : devices.get(0),20);
        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                disconnect_001(devices.size() == 0 ? null : devices.get(0));
                if (connectTimes > 1) {
                    connect_disconnect();
                    connectTimes = connectTimes - 1;
                }
            }
        },1000 * 10);

    }



    private void disconnect_001(BleDevice bleDevice) {
        try {
            Ble.getInstance().disconnect(bleDevice);
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }

    /**
     * stop scan test
     */
    private void stopscan_001() {
        try {
            Ble.getInstance().stopScan();
        } catch (Exception e) {
            toast(e.getMessage());
            e.printStackTrace();
        }
     }

    private void stopscan_002() {

        try {
            Ble.getInstance().stopScan();
        } catch (Exception e) {
            toast(e.getMessage());
            e.printStackTrace();
        }
    }

    private void finalize_001() {
        try {
            Ble.getInstance().finalize();
        } catch (ImkeyException e) {
            toast(e.getMessage());
        }
    }


    @Override
    public void finish() {
        Ble.getInstance().stopScan();
//        setResult(RESULT_CANCELED);
        super.finish();
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
        Ble.getInstance().stopScan();
        BleDevice bleDevice = devices.get(position);
        Intent intent = new Intent();
        intent.putExtra("bleDevice", bleDevice);
        setResult(RESULT_OK, intent);
        finish();
    }


    private void toast(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(BleTestActivity.this, msg, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
