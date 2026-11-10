package com.mk.imkeydemo.keycore;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/** Copies Rust-owned results before releasing the original native pointer. */
public interface RustApi extends Library {
    RustApi INSTANCE = new Adapter();
    String get_apdu();
    String set_apdu(String value);
    void set_apdu_return(String value);
    String get_apdu_return();
    void set_callback(Sender sender);
    String call_imkey_api(String value);
    void clear_err();
    String get_last_err_message();

    public interface NativeBindings extends Library {
        NativeBindings INSTANCE = Native.load("connector", NativeBindings.class);
        Pointer get_apdu();
        void set_apdu(String apdu);
        void set_apdu_return(String response);
        Pointer get_apdu_return();
        void set_callback(Sender sender);
        Pointer call_imkey_api(String value);
        void imkey_clear_err();
        Pointer imkey_get_last_err_message();
        void imkey_free_const_string(Pointer value);
    }

    final class Adapter implements RustApi {
        private Adapter() {}
        // JNA callback trampolines must not outlive their Java callback object.
        private Sender registeredCallback;
        private String copyAndFree(Pointer value) {
            if (value == null) return "";
            try {
                return value.getString(0, "UTF-8");
            } finally {
                NativeBindings.INSTANCE.imkey_free_const_string(value);
            }
        }

        public String get_apdu() { return copyAndFree(NativeBindings.INSTANCE.get_apdu()); }
        public String set_apdu(String value) { NativeBindings.INSTANCE.set_apdu(value); return ""; }
        public void set_apdu_return(String value) { NativeBindings.INSTANCE.set_apdu_return(value); }
        public String get_apdu_return() { return copyAndFree(NativeBindings.INSTANCE.get_apdu_return()); }
        public synchronized void set_callback(Sender sender) {
            NativeBindings.INSTANCE.set_callback(sender);
            registeredCallback = sender;
        }
        public String call_imkey_api(String value) { return copyAndFree(NativeBindings.INSTANCE.call_imkey_api(value)); }
        public void clear_err() { NativeBindings.INSTANCE.imkey_clear_err(); }
        public String get_last_err_message() { return copyAndFree(NativeBindings.INSTANCE.imkey_get_last_err_message()); }
    }
}
