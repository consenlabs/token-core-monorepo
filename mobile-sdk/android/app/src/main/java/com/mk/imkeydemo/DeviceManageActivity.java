package com.mk.imkeydemo;

import android.Manifest;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.mk.imkeylibrary.common.Applet;
import com.mk.imkeylibrary.exception.ImkeyException;
import com.mk.imkeylibrary.keycore.DeviceApi;
import com.mk.imkeylibrary.utils.LogUtil;


public class DeviceManageActivity extends AppCompatActivity {
    private static final int TYPE_BTC = 1;
    private static final int TYPE_ETH = 2;
    private static final int TYPE_EOS = 3;
    private static final int TYPE_IMK = 4;
    private static final int TYPE_USDT = 5;
    private static final int TYPE_COSMOS = 6;

    private ExecutorService es = Executors.newCachedThreadPool();
    private ProgressDialog pd;
    private Context mContext;
    private int type = TYPE_BTC;
    private String appletName = Applet.BTC_NAME;
    private EditText bleNameEdit;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_device_manage);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN);

        mContext = this;

        bleNameEdit = findViewById(R.id.edit_ble_name);

        pd = new ProgressDialog(this);
        pd.requestWindowFeature(Window.FEATURE_NO_TITLE);
        pd.setCanceledOnTouchOutside(false);
        pd.setCancelable(false);
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


    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_se_query:
                querySe();
                break;
            case R.id.btn_se_check:
                checkSe();
                break;
            case R.id.btn_se_active:
                activeSe();
                break;
            case R.id.btn_app_download:
                appDwonload();
                break;
            case R.id.btn_app_delete:
                appDelete();
                break;
            case R.id.btn_app_update:
                appUpdate();
                break;
            case R.id.radio_btc:
                type = TYPE_BTC;
                switchApplet();
                break;
            case R.id.radio_eth:
                type = TYPE_ETH;
                switchApplet();
                break;
            case R.id.radio_eos:
                type = TYPE_EOS;
                switchApplet();
                break;
            case R.id.radio_imk:
                type = TYPE_IMK;
                switchApplet();
                break;
            case R.id.radio_usdt:
                type = TYPE_USDT;
                switchApplet();
                break;
            case R.id.radio_cosmos:
                type = TYPE_COSMOS;
                switchApplet();
                break;
            case R.id.btn_set_ble_name:
                setBleName();
                break;

            default:
                break;
        }
    }

    private void switchApplet() {
        switch (type) {
            case TYPE_BTC:
                LogUtil.d("btc..");
                appletName = Applet.BTC_NAME;
                break;
            case TYPE_ETH:
                LogUtil.d("eth..");
                appletName = Applet.ETH_NAME;
                break;
            case TYPE_EOS:
                LogUtil.d("eos..");
                appletName = Applet.EOS_NAME;
                break;
            case TYPE_IMK:
                LogUtil.d("sio..");
                appletName = Applet.IMK_NAME;
                break;
            case TYPE_USDT:
                LogUtil.d("usdt..");
                appletName = Applet.BTC_NAME;
                break;
            case TYPE_COSMOS:
                LogUtil.d("cosmos..");
                appletName = Applet.COSMOS_NAME;
                break;
        }
    }

    private void querySe() {
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
//                    new CheckUpdateTest().checkUpdateTest();
                    String result = DeviceApi.checkUpdate().toString();
                    LogUtil.d(result);
                    toast("检查更新完成");
                }catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void checkSe() {
        pd.show();
        pd.setMessage("正在认证设备...");
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
//                    new CheckDeviceTest().checkDeviceTest();
//                    mManager.checkDevice();
                    DeviceApi.checkDevice();
                    toast("设备认证成功");
                }catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void activeSe() {
        pd.show();
        pd.setMessage("正在激活设备...");
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    DeviceApi.activeDevice();
//                    new ActiveDeviceTest().activeDeviceTest();
                    //mManager.activeDevice();
                    toast("设备激活成功");
                } catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void toast(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(DeviceManageActivity.this, msg, Toast.LENGTH_SHORT).show();
            }
        });
    }


    private void appUpdate() {
        pd.show();
        pd.setMessage("正在更新applet...");
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
//                    new AppUpdateTest().appUpdateTest();
//                    mManager.update(appletName);
                    DeviceApi.updateApplet(appletName);
                    toast("applet更新成功");
                } catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void appDwonload() {
        pd.show();
        pd.setMessage("正在下载applet...");
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    //new AppDownloadTest().appDownloadTest();
//                    mManager.download(appletName);
                    DeviceApi.downloadApplet(appletName);
                    toast("applet下载成功");
                } catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void appDelete() {
        pd.show();
        pd.setMessage("正在删除applet...");
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    //new AppDeleteTest().appDeleteTest();
//                    mManager.delete(appletName);
                    DeviceApi.deleteApplet(appletName);
                    toast("applet删除成功");
                } catch (ImkeyException e) {
                    toast(e.getMessage());
                }
                pdCancel();
            }
        });
    }

    private void setBleName() {

        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String bleName = bleNameEdit.getText().toString();
                DeviceApi.setBleName(bleName);
                toast("蓝牙名设置完成");
            }catch (ImkeyException e) {
                toast(e.getMessage());
            }
            pdCancel();
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

}
