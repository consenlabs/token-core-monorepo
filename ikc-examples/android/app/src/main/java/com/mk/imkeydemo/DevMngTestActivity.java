//package com.mk.imkeydemo;
//
//import android.app.Activity;
//import android.app.AlertDialog;
//import android.content.Context;
//import android.content.DialogInterface;
//import android.content.Intent;
//import android.os.Bundle;
//import android.support.annotation.Nullable;
//import android.view.View;
//import android.widget.AdapterView;
//import android.widget.ArrayAdapter;
//import android.widget.EditText;
//import android.widget.Toast;
//
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;
//
//import javax.crypto.KeyAgreement;
//
//import com.mk.imkeylibrary.bluetooth.Ble;
//import com.mk.imkeylibrary.bluetooth.BleDevice;
//import com.mk.imkeylibrary.device.DeviceManager;
//import com.mk.imkeylibrary.device.key.KeyConverter;
//import com.mk.imkeylibrary.device.model.AppUpdateResponse;
//import com.mk.imkeylibrary.device.model.SdkInfo;
//import com.mk.imkeylibrary.exception.ImkeyException;
//import com.mk.imkeylibrary.utils.ByteUtil;
//import com.mk.imkeylibrary.utils.LogUtil;
//
//public class DevMngTestActivity extends Activity implements AdapterView.OnItemClickListener {
//    private static final String TAG = "ble";
//    private Context mContext;
//    private List<String> deviceInfos;
//    private List<BleDevice> devices;
//    private ArrayAdapter<String> adapter;
//    private DeviceManager deviceManager;
//    private BleDevice bleDevice;
//    private ExecutorService es = Executors.newCachedThreadPool();
//    @Override
//    protected void onCreate(@Nullable Bundle savedInstanceState) {
//        super.onCreate(savedInstanceState);
//        setContentView(R.layout.activity_devmng);
//        mContext = this;
//        setFinishOnTouchOutside(true);
//
//        devices = new ArrayList<>();
//        bleDevice = (BleDevice)getIntent().getParcelableExtra("bleDevice");
//        deviceManager = new DeviceManager();
//    }
//
//    public void onClick(View view) {
////        mTxtInfo.setText(null);
//        switch (view.getId()) {
//
//            // test getinstance
//            case R.id.btn_getseid_001:
//                getSeid_001();
//                break;
//            case R.id.btn_getseid_002:
//                getSeid_002();
//                break;
//            case R.id.btn_getseid_003:
//                getSeid_003();
//                break;
//            case R.id.btn_getfirmwareversion_001:
//                getFirmwareVersion_001();
//                break;
//            case R.id.btn_checkUpdate_001:
//                checkUpdate_001();
//                break;
//            case R.id.btn_activeDevice_001:
//                activeDevice_001();
//                break;
//            case R.id.btn_checkDevice_001:
//                checkDevice_001();
//                break;
//            case R.id.btn_download_001:
//                download_001();
//                break;
//            case R.id.btn_update_001:
//                update_001();
//                break;
//            case R.id.btn_delete_001:
//                delete_001();
//                break;
//            // test start scan
//            case R.id.btn_getBatteryPower_001:
//                getBatteryPower_001();
//                break;
//            case R.id.btn_bindCheck_001:
//                bindCheck_001();
//                break;
//            case R.id.btn_disBindCode_001:
//                disBindCode_001();
//                break;
//            case R.id.btn_bindAcquire_001:
//                bindAcquire_001();
//                break;
//            case R.id.btn_test_key:
//                testKey();
//                break;
//            case R.id.btn_get_sdkinfo:
//                getSdkInfo();
//                break;
//            default:
//                break;
//        }
//    }
//
//    private void testKey(){
//        try {
//            String appPrvkey = "44DD587E45A3B8936CF367E6B38E3FD40E5C4390B4C04B7BC7082A766B442AA4";
//            String sePubkey = "04A609910703E61E5E924A0889468C8BFBB0F37751F786100ED31F593394A68FB4E6F8E31BC8A2CEDC9243FC96664512CEFD6A4378A751593BEFA1D8063D1183DC";
//            PrivateKey privateKey = KeyConverter.getPrivKey(ByteUtil.hexStringToByteArray(appPrvkey));
//            PublicKey publicKey = KeyConverter.getPubKey(ByteUtil.hexStringToByteArray(sePubkey));
//
//            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "SC");
//            ka.init(privateKey);
//            ka.doPhase(publicKey, true);
//
//            byte[] sessionKey = ka.generateSecret();
////            sessionKey = Hash.sha1(sessionKey);
////            byte[] aesSessionKey = new byte[16];
////            System.arraycopy(sessionKey, 0, aesSessionKey, 0, 16);
//            String ss = ByteUtil.byteArrayToHexString(sessionKey);
//            LogUtil.d(ss);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void getSdkInfo(){
//
//        SdkInfo sdkInfo = deviceManager.getSdkInfo();
//        toast("sdkVersion:" + sdkInfo.getSdkVersion());
//    }
//
//
//    private void search() {
//
//    }
//
//    /**
//     * getInstance test
//     */
//    private void getSeid_001() {
//        try {
//            String seid= deviceManager.getSeId();
//            if (seid == null || "".equals(seid) || seid.length() != 32){
//                toast("查询SEID失败");
//            }else{
//                toast("查询SEID成功：" + seid);
//            }
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void getSeid_002() {
//        try {
//            String seid= deviceManager.getSeId();
//            if (seid == null || "".equals(seid) || seid.length() != 32){
//                toast("查询SEID失败");
//            }else{
//                toast("查询SEID成功：" + seid);
//            }
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void getSeid_003() {
//        try {
//            String seid = "";
//            String testResult = "";
//            for (int i = 0; i < 5; i++){
//                seid = deviceManager.getSeId();
//                testResult += (seid + "\n");
//
//            }
//            toast("查询SEID成功：" + testResult);
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    /**
//     * getInstance test
//     */
//    private void getFirmwareVersion_001() {
//        try {
//            String version = deviceManager.getFirmwareVersion();
//            toast(version);
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void checkUpdate_001() {
//        try {
//            Ble ble = Ble.getInstance();
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try {
//                        deviceManager.checkUpdate();
//                        toast("设备信息检索成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void activeDevice_001() {
//        try {
//            Ble ble = Ble.getInstance();
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try {
//                        deviceManager.activeDevice();
//                        toast("设备激活成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void checkDevice_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try {
//                        deviceManager.checkDevice();
//                        toast("设备认证成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void download_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try {
////                        deviceManager.download(appletName);//BTC、ETH
//                        deviceManager.download("BTC");
//                        toast("applet下载成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void update_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    AppUpdateResponse response = null;
//                    try {
//                        deviceManager.update("BTC");
//                        toast("applet更新成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void delete_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try {
//                        deviceManager.delete("BTC");
//                        toast("applet删除成功");
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void getBatteryPower_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try { ;
//                        toast(deviceManager.getBatteryPower());
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void bindCheck_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try { ;
//                        toast(deviceManager.bindCheck());
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void disBindCode_001() {
//        try {
//            es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try { ;
//                        deviceManager.displayBindingCode();
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    private void bindAcquire_001() {
//        try {
//
//            final EditText inputAuthCode = new EditText(this);
//            inputAuthCode.setText("rvyqnb98");
//            AlertDialog.Builder builder = new AlertDialog.Builder(this);
//            builder.setTitle("授权码").setIcon(android.R.drawable.ic_dialog_info).setView(inputAuthCode)
//                    .setNegativeButton("Cancel", null);
//            builder.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
//
//                public void onClick(DialogInterface dialog, int which) {
//                    es.execute(new Runnable() {
//                        @Override
//                        public void run() {
//                            try {
//                                deviceManager.bindAcquire(inputAuthCode.getText().toString());
//                            } catch (ImkeyException e) {
//                                toast(e.getMessage());
//                            }
//                        }
//                    });
//
//                }
//            });
//            builder.show();
//
//            /*es.execute(new Runnable() {
//                @Override
//                public void run() {
//                    try { ;
//                        toast(deviceManager.bindAcquire("ABCD5678"));
//                    } catch (ImkeyException e) {
//                        toast(e.getMessage());
//                    }
//                }
//            });*/
//        } catch (Exception e) {
//            toast(e.getMessage());
//        }
//    }
//
//    /**
//     * stop scan test
//     */
//    private void stopscan_001() {
//        try {
//            Ble.getInstance().stopScan();
//        } catch (Exception e) {
//            toast(e.getMessage());
//            e.printStackTrace();
//        }
//    }
//
//    private void stopscan_002() {
//
//        //search first
//
//
//        try {
//            Ble.getInstance().stopScan();
//        } catch (Exception e) {
//            toast(e.getMessage());
//            e.printStackTrace();
//        }
//    }
//
//
//    @Override
//    public void finish() {
//        Ble.getInstance().stopScan();
////        setResult(RESULT_CANCELED);
//        super.finish();
//    }
//
//    @Override
//    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
//        Ble.getInstance().stopScan();
//        BleDevice bleDevice = devices.get(position);
//        Intent intent = new Intent();
//        intent.putExtra("bleDevice", bleDevice);
//        setResult(RESULT_OK, intent);
//        finish();
//    }
//
//
//    private void toast(final String msg) {
//        runOnUiThread(new Runnable() {
//            @Override
//            public void run() {
//                Toast.makeText(DevMngTestActivity.this, msg, Toast.LENGTH_SHORT).show();
//            }
//        });
//    }
//}
