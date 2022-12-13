package com.mk.imkeydemo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.bluetooth.BleDevice;


public class BusinessTestActivity extends Activity implements AdapterView.OnItemClickListener {
    private static final String TAG = "ble";
    private Context mContext;
    private List<String> deviceInfos;
    private List<BleDevice> devices;
    private ArrayAdapter<String> adapter;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_business);
        mContext = this;
        setFinishOnTouchOutside(true);

        devices = new ArrayList<>();

    }

    public void onClick(View view) {
//        mTxtInfo.setText(null);
        switch (view.getId()) {

            // test getinstance
            case R.id.btc_getAddress_001:
                getinst_001();
                break;
            case R.id.btn_getseid_002:
                getinst_002();
                break;
            // test start scan

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
        } catch (Exception e) {
            toast(e.getMessage());
        }
    }

    private void getinst_002() {
        try {
            Ble ble = Ble.getInstance();
            toast(ble.toString());
        } catch (Exception e) {
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

        //search first


        try {
            Ble.getInstance().stopScan();
        } catch (Exception e) {
            toast(e.getMessage());
            e.printStackTrace();
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
                Toast.makeText(BusinessTestActivity.this, msg, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
