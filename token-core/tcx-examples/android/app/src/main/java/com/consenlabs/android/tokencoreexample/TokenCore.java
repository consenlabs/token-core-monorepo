package com.consenlabs.android.tokencoreexample;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/** Keeps Java String callers separate from Rust's owned C-string ABI. */
public final class TokenCore {
    public static final TokenCore INSTANCE = new TokenCore();
    private TokenCore() {}
    public interface NativeBindings extends Library {
        NativeBindings INSTANCE = Native.load("tcx", NativeBindings.class);
        void init_token_core_x(String json);
        Pointer call_tcx_api(String value);
        void clear_err();
        Pointer get_last_err_message();
        void free_const_string(Pointer value);
    }
    private String copyAndFree(Pointer value) {
        if (value == null) return "";
        try { return value.getString(0, "UTF-8"); }
        finally { NativeBindings.INSTANCE.free_const_string(value); }
    }
    public void init_token_core_x(String json) { NativeBindings.INSTANCE.init_token_core_x(json); }
    public String call_tcx_api(String value) { return copyAndFree(NativeBindings.INSTANCE.call_tcx_api(value)); }
    public void clear_err() { NativeBindings.INSTANCE.clear_err(); }
    public String get_last_err_message() { return copyAndFree(NativeBindings.INSTANCE.get_last_err_message()); }
}
