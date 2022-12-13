package com.mk.imkeydemo.excepttest.devicemanger;

import com.google.protobuf.Any;
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;

public class ActiveDeviceTest {

    public void activeDeviceTest() {

        String error = null;

        //imkey_tsm_device_stop_using
        RustApi.INSTANCE.clear_err();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("device_activate")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            error = RustApi.INSTANCE.get_last_err_message();
            api.Api.Response response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            response.getIsSuccess();
            error = response.getError();

            LogUtil.e("期望结果：imkey_tsm_device_stop_using" + "，实际结果：" + error);

        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
