package im.imkey.imkeylibrary.bluetooth;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothDevice;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;

import com.ftsafe.bluetooth.key.jkey.FTBluetoothDevice;

public class BleDevice implements Parcelable {
    private final BluetoothDevice bluetoothDevice;
    private final int devType;
    private final int devRssi;
    private final String radioDevName;
    private final String radioDevUUID;
    private final String radioManufacturerData;

    public BleDevice(BluetoothDevice bluetoothDevice) {
        this.bluetoothDevice = bluetoothDevice;
        this.devType = 0;
        this.radioDevName = "";
        this.radioDevUUID = "";
        this.devRssi = 0;
        this.radioManufacturerData = "";
    }

    public BleDevice(BluetoothDevice bluetoothDevice, int devType, String radioDevName, String radioDevUUID, int devRssi, String radioManufacturerData) {
        this.bluetoothDevice = bluetoothDevice;
        this.devType = devType;
        this.radioDevName = radioDevName;
        this.radioDevUUID = radioDevUUID;
        this.devRssi = devRssi;
        this.radioManufacturerData = radioManufacturerData;
    }

    protected BleDevice(Parcel in) {
        bluetoothDevice = in.readParcelable(BluetoothDevice.class.getClassLoader());
        devType = in.readInt();
        devRssi = in.readInt();
        radioDevName = in.readString();
        radioDevUUID = in.readString();
        radioManufacturerData = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeParcelable(bluetoothDevice, flags);
        dest.writeInt(devType);
        dest.writeInt(devRssi);
        dest.writeString(radioDevName);
        dest.writeString(radioDevUUID);
        dest.writeString(radioManufacturerData);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<BleDevice> CREATOR = new Creator<BleDevice>() {
        @Override
        public BleDevice createFromParcel(Parcel in) {
            return new BleDevice(in);
        }

        @Override
        public BleDevice[] newArray(int size) {
            return new BleDevice[size];
        }
    };

    public final BluetoothDevice getBluetoothDevice() {
        return this.bluetoothDevice;
    }

    public final int getDevType() {
        return this.devType;
    }

    public final int getDevRssi() {
        return this.devRssi;
    }

    public final String getRadioUUID() {
        return this.radioDevUUID;
    }

    public final String getRadioDevName() {
        return this.radioDevName;
    }

    public final String getRadioManufacturerData() {
        return this.radioManufacturerData;
    }

    public final boolean equals(Object bluetoothDevice) {
        return bluetoothDevice instanceof FTBluetoothDevice && this.bluetoothDevice.equals(((FTBluetoothDevice) bluetoothDevice).getBluetoothDevice());
    }

    public final int hashCode() {
        return this.bluetoothDevice.hashCode();
    }

    public final String toString() {
        @SuppressLint("MissingPermission") String var1 = this.bluetoothDevice.getName();
        return (TextUtils.isEmpty(var1) ? this.radioDevName : var1) + "\n" + this.bluetoothDevice.getAddress();
    }
}
