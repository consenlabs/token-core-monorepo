package im.imkey.bledemo;

import android.Manifest;
import android.app.ProgressDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothManager;
import android.content.Context;
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

import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.Callback.ConnectCallback;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;
import im.imkey.imkeylibrary.utils.LogUtil;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "imkey";
    private TextView mTxtState;

    private ProgressDialog pd;
    private Context mContext;
    private BleDevice mDevice;//current connect device
    private TextView mTvResult;

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
        mTvResult = findViewById(R.id.tv_result);

        initPermission();
        openBluetooth();
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
            case R.id.btn_send:
                sendApdu();
                break;

            default:
                break;
        }
    }

    private void sendApdu(){
        EditText editText = findViewById(R.id.et_apdu);
        String apdu = editText.getText().toString();
        String res = Ble.getInstance().sendApdu(apdu);
        showResult(res);
    }

    private void showResult(String result){
        mTvResult.setText("");
        mTvResult.setText(result);
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
