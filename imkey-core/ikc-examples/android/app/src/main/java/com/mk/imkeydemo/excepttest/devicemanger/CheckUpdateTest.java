package com.mk.imkeydemo.excepttest.devicemanger;


import com.mk.imkeydemo.keycore.RustApi;

import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class CheckUpdateTest {

    public void checkUpdateTest() {

        String error = null;

        //imkey_tsm_device_stop_using
        RustApi.INSTANCE.clear_err();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("check_update")
                .build();
        String hex = ByteUtil.byteArrayToHexString(action.toByteArray());
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
