package com.mk.imkeydemo.keycore;

import android.os.SystemClock;



import im.imkey.imkeylibrary.bluetooth.Ble;
import im.imkey.imkeylibrary.utils.LogUtil;

public class Api {

    public static void startMessageDeamon(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (true){
                    LogUtil.d("start while...");
                    String apdu = "";
                    while (true){
                        apdu = RustApi.INSTANCE.get_apdu();
                        if (!apdu.equals("")){
                            RustApi.INSTANCE.set_apdu("");
                            break;
                        }
                        SystemClock.sleep(1000);
                    }

                    String res = Ble.getInstance().sendApdu(apdu);

                    String apduRet = "";
                    while (true){
                        apduRet = RustApi.INSTANCE.get_apdu_return();
                        if(apduRet.equals("")){
                            RustApi.INSTANCE.set_apdu_return(res);
                            break;
                        }
                        SystemClock.sleep(1000);
                    }

                }
            }
        }).start();
    }

    private static final CallbackResponseBuffer CALLBACK_RESPONSE = new CallbackResponseBuffer();

    public static Sender sender = new Sender() {
        @Override
        public com.sun.jna.Pointer sendApdu(String apdu, int timeout) {
            LogUtil.d("set call back sucess");
            // The request is borrowed from Rust; never free a JNA-marshalled String.
            String result = "";
            try {
                result = Ble.getInstance().sendApdu(apdu,timeout);
            }catch (Exception e){
                result = "communication_error_" + e.getMessage();
            }
            return CALLBACK_RESPONSE.store(result);
        }
    };

    public static void setCallback(){
        RustApi.INSTANCE.set_callback(sender);
    }

}
