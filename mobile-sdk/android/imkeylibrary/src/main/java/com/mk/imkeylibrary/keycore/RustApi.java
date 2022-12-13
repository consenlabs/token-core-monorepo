package com.mk.imkeylibrary.keycore;

import com.mk.imkeylibrary.utils.Sender;
import com.sun.jna.Library;
import com.sun.jna.Native;

public interface RustApi extends Library{

    RustApi INSTANCE = (RustApi) Native.load("connector",RustApi.class);

    String get_apdu();
    String set_apdu(String apdu);
    void set_apdu_return(String apdu_return);
    String get_apdu_return();
    void set_callback(Sender sender);
    void free_const_string(String str);

    String call_imkey_api(String value);
    void clear_err();
    String get_last_err_message();
}
