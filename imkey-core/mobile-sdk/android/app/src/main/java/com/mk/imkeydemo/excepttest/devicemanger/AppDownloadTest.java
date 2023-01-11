package com.mk.imkeydemo.excepttest.devicemanger;

import com.google.protobuf.Any;
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;


public class AppDownloadTest {

    public void appDownloadTest() {

        String appName = "BTC";
        String appName2 = "TEST";
        String error = null;

        //imkey_illegal_prarm
        RustApi.INSTANCE.clear_err();

        deviceapi.Device.AppDownloadReq req = deviceapi.Device.AppDownloadReq.newBuilder()
                .setAppName(appName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_download")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            error = RustApi.INSTANCE.get_last_err_message();
            api.Api.Response response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            response.getIsSuccess();
            error = response.getError();

            LogUtil.e("期望结果：imkey_illegal_prarm" + "，实际结果：" + error);

        } catch (Exception e) {
            e.printStackTrace();
        }


        RustApi.INSTANCE.clear_err();

        req = deviceapi.Device.AppDownloadReq.newBuilder()
                .setAppName(appName2)
                .build();

        any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_download")
                .setParam(any)
                .build();

        hex = NumericUtil.bytesToHex(action.toByteArray());
        try {
            RustApi.INSTANCE.call_imkey_api(hex);
            error = RustApi.INSTANCE.get_last_err_message();
            api.Api.Response response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            response.getIsSuccess();
            error = response.getError();

            LogUtil.e("期望结果：imkey_app_name_not_exist" + "，实际结果：" + error);

        } catch (Exception e) {
            e.printStackTrace();
        }


        //设备未激活，需要改后台数据测试
        RustApi.INSTANCE.clear_err();

        req = deviceapi.Device.AppDownloadReq.newBuilder()
                .setAppName(appName)
                .build();

        any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_download")
                .setParam(any)
                .build();
        hex = NumericUtil.bytesToHex(action.toByteArray());
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            error = RustApi.INSTANCE.get_last_err_message();
            api.Api.Response response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            response.getIsSuccess();
            error = response.getError();

            LogUtil.e("期望结果：imkey_tsm_device_not_activated" + "，实际结果：" + error);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
