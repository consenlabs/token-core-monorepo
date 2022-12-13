package com.mk.imkeylibrary.keycore;

import android.text.TextUtils;

import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.exception.ImkeyException;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;
import com.mk.imkeylibrary.utils.Sender;

import im.imkey.imkeylibrary.bluetooth.Ble;

public class Api {
    private Api() {
        setCallback();
    }

    public static Api getInstance() {
        return Api.Holder.sInstance;
    }

    private static class Holder {
        private static Api sInstance = new Api();
    }

    public static Sender sender = new Sender() {
        @Override
        public String sendApdu(String apdu, int timeout) {
            RustApi.INSTANCE.free_const_string(apdu);
            String result = "";
            try {
                result = Ble.getInstance().sendApdu(apdu,timeout);
            }catch (Exception e){
                result = "communication_error_" + e.getMessage();
            }
            return result;
        }
    };

    private void setCallback(){
        RustApi.INSTANCE.set_callback(sender);
    }

    public byte[] callApi(String paramHex) {
        RustApi.INSTANCE.clear_err();
        String res = RustApi.INSTANCE.call_imkey_api(paramHex);
        String error = RustApi.INSTANCE.get_last_err_message();
        if(!TextUtils.isEmpty(error)){
            api.Api.Response response = null;
            try {
                response = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
            } catch (InvalidProtocolBufferException e) {
                e.printStackTrace();
                throw new ImkeyException(e.getMessage());
            }
            if(!response.getIsSuccess()){
                throw new ImkeyException(response.getError());
            }
        }

        return NumericUtil.hexToBytes(res);
    }
}
