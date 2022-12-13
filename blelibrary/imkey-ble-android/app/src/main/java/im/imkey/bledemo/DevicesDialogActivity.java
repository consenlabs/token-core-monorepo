package im.imkey.bledemo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.bluetooth.BleDevice;
import im.imkey.imkeylibrary.bluetooth.Callback.ScanCallback;
import im.imkey.imkeylibrary.bluetooth.ErrorCode;

public class DevicesDialogActivity extends Activity implements AdapterView.OnItemClickListener {
    private static final String TAG = "ble";
    private Context mContext;
    private List<String> deviceInfos;
    private List<BleDevice> devices;
    private ArrayAdapter<String> adapter;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_devices);
        mContext = this;
        setFinishOnTouchOutside(true);
//        Ble.getInstance().initialize(mContext);
        devices = new ArrayList<>();
        deviceInfos = new ArrayList<>();
        ListView listView = findViewById(R.id.list_devices);
        adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_expandable_list_item_1,
                deviceInfos);
        listView.setAdapter(adapter);
        listView.setOnItemClickListener(this);
        search();
    }

    private void search() {
        devices.clear();
        adapter.notifyDataSetChanged();

        Ble.getInstance().startScan(20, new ScanCallback() {
            @Override
            public void onScanStarted() {
                Log.d(TAG, "scan start...");
            }

            @Override
            public void onScanDevice(BleDevice bleDevice) {
                devices.add(bleDevice);
                deviceInfos.add(bleDevice.toString());
                adapter.notifyDataSetChanged();
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
}
