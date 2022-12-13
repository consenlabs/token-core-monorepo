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

    public static Sender sender = new Sender() {
        @Override
        public String sendApdu(String apdu, int timeout) {
            LogUtil.d("set call back sucess");
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

    public static void setCallback(){
        RustApi.INSTANCE.set_callback(sender);
    }

}
