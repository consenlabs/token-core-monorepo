package com.mk.imkeydemo;

import android.Manifest;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.mk.imkeydemo.excepttest.devicemanger.DeviceBindingTest;
import com.mk.imkeydemo.keycore.Api;
import com.mk.imkeydemo.keycore.DeviceBidingExample;
import com.mk.imkeydemo.keycore.DeviceManager;
import com.mk.imkeydemo.keycore.SdkInfo;
import com.sun.jna.Library;
import com.sun.jna.Native;

import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.Callback.ConnectCallback;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;
import im.imkey.imkeylibrary.utils.LogUtil;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "imkey";
    private TextView mTxtState;

    private ExecutorService es = Executors.newCachedThreadPool();
    private ProgressDialog pd;
    private Context mContext;
    private BleDevice mDevice;//current connect device
    private DeviceManager mManager;

   static {
       System.loadLibrary("crypto");
       System.loadLibrary("ssl");
   }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN);

        mContext = this;

//        Locale locale = getResources().getConfiguration().locale;
        Ble.getInstance().initialize(mContext,new Locale("en"));

        mTxtState = findViewById(R.id.text_state);
        pd = new ProgressDialog(this);
        pd.requestWindowFeature(Window.FEATURE_NO_TITLE);
        pd.setCanceledOnTouchOutside(false);
        pd.setCancelable(false);

        initPermission();
        openBluetooth();

//        String hi = hello("miao");
//        LogUtil.d(hi);
//
//        String xpub = getXPub();
//        LogUtil.d("xpub:" + xpub);

//        LogUtil.d("x3:" + CTreble.INSTANCE.treble(1));
//        LogUtil.d("x3:" + CTreble.INSTANCE.jni_call_static_method_safe());

//        int num = ThingLibrary.INSTANCE.dupli(14);
//        LogUtil.d("num:" + num);

        //hello rust
//        LogUtil.hh();

//        factAndCallMeBack(2,new Test());


//        LogUtil.installApplet();

//        Api.initRustLog();
//        Api.startMessageDeamon();
//        Api.check_update();
        Api.setCallback();

    }

    //android 6.0 以上需要动态申请权限
    private void initPermission() {
        if (Build.VERSION.SDK_INT >= 23 && mContext.getApplicationInfo().targetSdkVersion >= 23) {
            String permissions[] =
                    {
                            Manifest.permission.BLUETOOTH_ADMIN,
                            Manifest.permission.BLUETOOTH,
                            Manifest.permission.WAKE_LOCK,
                            Manifest.permission.ACCESS_COARSE_LOCATION,
                            Manifest.permission.ACCESS_FINE_LOCATION
                    };

            ArrayList<String> toApplyList = new ArrayList<String>();

            for (String perm : permissions) {
                if (PackageManager.PERMISSION_GRANTED != this.checkSelfPermission(perm)) {
                    toApplyList.add(perm); //进入到这里代表没有权限.
                }
            }
            String tmpList[] = new String[toApplyList.size()];
            if (!toApplyList.isEmpty()) {
                this.requestPermissions(toApplyList.toArray(tmpList), 1);
            }
        }
    }

    private void openBluetooth() {
        BluetoothAdapter bluetoothAdapter = BluetoothAdapter
                .getDefaultAdapter();
        if (bluetoothAdapter == null) {
            Toast.makeText(this, "不支持蓝牙", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!bluetoothAdapter.isEnabled()) {
            bluetoothAdapter.enable();
        }
    }


    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_scan:
                showSearchDialog();
                break;
            case R.id.btn_disconnect:
                disConnect();
                break;
            case R.id.btn_device_info:
                showDeviceInfo(mDevice.getBluetoothDevice().getName(),mDevice.getBluetoothDevice().getAddress());
                break;
            case R.id.btn_bind:
                matchDevice(mDevice.getBluetoothDevice().getAddress());
                break;
            case R.id.btn_btc:
                goBtc();
                break;
            case R.id.btn_eth:
                goEth();
                break;
            case R.id.btn_eos:
                goEos();
                break;
            case R.id.btn_cosmos:
                goCosmos();
                break;
            case R.id.btn_device_manage:
                goDeviceManage();
                break;
            case R.id.btn_filecoin:
                goFilecoin();
                break;
            default:
                break;
        }
    }

    private void showDeviceInfo(String name,String mac){
        mTxtState.setText("");
        mTxtState.append("蓝牙名称：" + name);
        mTxtState.append("\n蓝牙地址：" + mac);
        pd.setMessage("获取设备信息...");
        pd.show();
        es.execute(new Runnable() {
            @Override
            public void run() {
                final String bleVersion = mManager.getBleVersion();
                final String seid = mManager.getSeId();
                final int ramSize = mManager.getRamSize();
                final String battery = mManager.getBatteryPower();
                final String lifeCycle = mManager.getLifeTime();
                final String sn = mManager.getSn();
                final String firmwareVersion = mManager.getFirmwareVersion();
                final String bleName = mManager.getBleName();
                final SdkInfo sdkInfo = mManager.getSdkInfo();

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        mTxtState.append("\n蓝牙版本：" + bleVersion);
                        mTxtState.append("\nseid：" + seid);
                        mTxtState.append("\n剩余空间：" + ramSize);
                        mTxtState.append("\n剩余电量：" + battery);
                        mTxtState.append("\n生命周期：" + lifeCycle);
                        mTxtState.append("\n固件版本：" + firmwareVersion);
                        mTxtState.append("\n蓝牙名称：" + bleName);
                        mTxtState.append("\nSDK版本：" + sdkInfo.getSdkVersion());
                        mTxtState.append("\nsn：" + sn);
                        pd.cancel();
                    }
                });
            }
        });
    }

    private void goBtc(){
        Intent intent = new Intent(mContext,BtcActivity.class);
        startActivity(intent);
    }

    private void goEth(){
        Intent intent = new Intent(mContext,EthActivity.class);
        startActivity(intent);
    }
    private void goEos(){
        Intent intent = new Intent(mContext,EosActivity.class);
        startActivity(intent);
    }

    private void goCosmos(){
        Intent intent = new Intent(mContext,CosmosActivity.class);
        startActivity(intent);
    }

    private void goDeviceManage(){
        Intent intent = new Intent(mContext,DeviceManageActivity.class);
        startActivity(intent);
    }

    private void goFilecoin(){
        Intent intent = new Intent(mContext,FilecoinActivity.class);
        startActivity(intent);
    }

    private void showSearchDialog() {
        Intent intent = new Intent(mContext, DevicesDialogActivity.class);
        startActivityForResult(intent, 11);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        switch (requestCode) {
            case 11:
                if (resultCode == RESULT_OK) {
                    BleDevice bleDevice = data.getParcelableExtra("bleDevice");
                    connect(bleDevice);
                } else {
                    Ble.getInstance().stopScan();
                }
                break;
        }
    }

    private void connect(BleDevice bleDevice) {
        Ble.getInstance().connect(bleDevice, 30, new ConnectCallback() {
            @Override
            public void onConnecting(BleDevice bleDevice) {
                Log.d(TAG, "onConnecting... " + bleDevice.toString());
                pd.setMessage("正在连接...");
                pd.show();
            }

            @Override
            public void onConnected(BleDevice bleDevice) {
                mDevice = bleDevice;
                Log.d(TAG, "onConnected... " + bleDevice.toString());
                mTxtState.setText("");
                mTxtState.append("蓝牙名称：" + mDevice.getBluetoothDevice().getName());
                mTxtState.append("\n蓝牙地址：" + mDevice.getBluetoothDevice().getAddress());
                pd.dismiss();
                mManager = new DeviceManager();

                // ble status
                BluetoothManager bm = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
                int status = bm.getConnectionState(bleDevice.getBluetoothDevice(), BluetoothGatt.GATT);
                LogUtil.d(status + "");

            }

            @Override
            public void onDisconnected(BleDevice bleDevice) {
                Log.d(TAG, "onDisconnected... " + bleDevice.toString());
                mTxtState.setText("");
            }

            @Override
            public void onConnectFail(ErrorCode errorCode) {
                Log.d(TAG, "onConnectFail... " + errorCode.toString() + errorCode.get_desc());
                pd.dismiss();
                Toast.makeText(mContext, errorCode.get_desc(), Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void matchDevice(final String deviceMac){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    String status = mManager.bindCheck(mContext);
                    if("unbound".equals(status)){
                        mManager.displayBindingCode();
                        bindDevice(status,deviceMac);
                    }else if("bound_other".equals(status)){
                        String bindCode = SpTool.ins(mContext).getBindCode(deviceMac);
                        if(!bindCode.isEmpty()){
                            toast("已绑定其他设备,重新绑定..");
                            String res = mManager.bindAcquire(bindCode);
                            if(!"success".equals(res)){
                                bindDevice(status,deviceMac);
                            }
                        }else{
                            toast("未绑定过的设备，请输入绑定码");
                            bindDevice(status,deviceMac);
                        }
                    }else{
                        toast("已绑定");
                    }
                } catch (Exception e) {
                    toast(e.getMessage());
                }
            }
        });
    }

    private void bindDevice(final String status,final String deviceMac){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                final EditText inputAuthCode = new EditText(mContext);
                inputAuthCode.setHint("input bind code");
                AlertDialog.Builder builder = new AlertDialog.Builder(mContext);
                builder.setTitle(status).setView(inputAuthCode)
                        .setNegativeButton("Cancel", null);
                builder.setPositiveButton("Ok", new DialogInterface.OnClickListener() {

                    public void onClick(DialogInterface dialog, int which) {
                        es.execute(new Runnable() {
                            @Override
                            public void run() {
                                // error test
                                new DeviceBindingTest().deviceBingdingTest2(inputAuthCode.getText().toString());
                            }
                        });

                    }
                });
                builder.show();
            }
        });
    }



    private void disConnect() {
        if (mDevice != null)
            Ble.getInstance().disconnect(mDevice);
    }


    private void showProgressDialog(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pd.show();
                pd.setMessage(msg);
            }
        });
    }

    private void toast(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, msg, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void pdNotice(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pd.setMessage(msg);
            }
        });
    }

    private void pdCancel() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pd.cancel();
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Ble.getInstance().finalize();
    }
}
