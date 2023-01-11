package com.mk.imkeydemo.excepttest.devicemanger;

import com.google.protobuf.Any;
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;

public class DeviceBindingTest {

    public void deviceBingdingTest() {

        String error = null;
        String bindCode = "123456789";

        deviceapi.Device.BindAcquireReq req = deviceapi.Device.BindAcquireReq.newBuilder()
                .setBindCode(bindCode)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_acquire")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            error = RustApi.INSTANCE.get_last_err_message();
            api.Api.Response response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            response.getIsSuccess();
            error = response.getError();

            LogUtil.e("期望结果：imkey_sdk_illegal_argument" + "，实际结果：" + error);

        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
