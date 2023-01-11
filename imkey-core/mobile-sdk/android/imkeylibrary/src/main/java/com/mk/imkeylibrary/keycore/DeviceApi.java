package com.mk.imkeylibrary.keycore;

import android.content.Context;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.common.Messages;
import com.mk.imkeylibrary.exception.ImkeyException;
import com.mk.imkeylibrary.utils.NumericUtil;


import deviceapi.Device;

public class DeviceApi {

    public static Device.CheckUpdateRes checkUpdate() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("check_update")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);

        Device.CheckUpdateRes result = null;
        try {
            result = Device.CheckUpdateRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static void checkDevice() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("device_secure_check")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static void activeDevice() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("device_activate")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static void updateApplet(String appletName) {
        deviceapi.Device.AppUpdateReq req = deviceapi.Device.AppUpdateReq.newBuilder()
                .setAppName(appletName)
                .build();
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_update")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static void deleteApplet(String appletName) {
        deviceapi.Device.AppUpdateReq req = deviceapi.Device.AppUpdateReq.newBuilder()
                .setAppName(appletName)
                .build();
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_delete")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static void downloadApplet(String appletName) {
        deviceapi.Device.AppUpdateReq req = deviceapi.Device.AppUpdateReq.newBuilder()
                .setAppName(appletName)
                .build();
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_download")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static String bindCheck(Context context) {
        if (null == context) {
            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
        }
        String filePath = context.getFilesDir().getPath();

        deviceapi.Device.BindCheckReq req = deviceapi.Device.BindCheckReq.newBuilder()
                .setFilePath(filePath)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_check")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Device.BindCheckRes result = null;
        try {
            result = Device.BindCheckRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getBindStatus();
    }

    public static String bindAcquire(String bindingCode) {

        deviceapi.Device.BindAcquireReq req = deviceapi.Device.BindAcquireReq.newBuilder()
                .setBindCode(bindingCode)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_acquire")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Device.BindAcquireRes result = null;
        try {
            result = Device.BindAcquireRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getBindResult();
    }

    public static void displayBindCode() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_display")
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Api.getInstance().callApi(hex);
    }

    public static String getSeId() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_seid")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetSeidRes result = null;
        try {
            result = Device.GetSeidRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getSeid();
    }

    public static String getSn() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_sn")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetSnRes result = null;
        try {
            result = Device.GetSnRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getSn();
    }

    public static String getRamSize() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ram_size")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetRamSizeRes result = null;
        try {
            result = Device.GetRamSizeRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getRamSize();
    }

    public static String getFirmwareVersion() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_firmware_version")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetFirmwareVersionRes result = null;
        try {
            result = Device.GetFirmwareVersionRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getFirmwareVersion();
    }

    public static String getBatteryPower() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_battery_power")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetBatteryPowerRes result = null;
        try {
            result = Device.GetBatteryPowerRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getBatteryPower();
    }

    public static String getLifeTime() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_life_time")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetLifeTimeRes result = null;
        try {
            result = Device.GetLifeTimeRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getLifeTime();
    }

    public static String getBleName() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ble_name")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetBleNameRes result = null;
        try {
            result = Device.GetBleNameRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getBleName();
    }

    public static void setBleName(String bleName) {
        deviceapi.Device.SetBleNameReq req = deviceapi.Device.SetBleNameReq.newBuilder()
                .setBleName(bleName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("set_ble_name")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        Api.getInstance().callApi(hex);
    }

    public static String getBleVersion() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ble_version")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetBleVersionRes result = null;
        try {
            result = Device.GetBleVersionRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getBleVersion();
    }

    public static Device.GetSdkInfoRes getSdkInfo() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_sdk_info")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Device.GetSdkInfoRes result = null;
        try {
            result = Device.GetSdkInfoRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }
}
