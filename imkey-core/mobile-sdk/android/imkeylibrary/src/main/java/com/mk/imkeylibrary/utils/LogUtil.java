package com.mk.imkeylibrary.utils;

import android.os.SystemClock;
import android.util.Log;

import com.mk.imkeylibrary.BuildConfig;
import com.sun.jna.Library;
import com.sun.jna.Native;


public class LogUtil {
    private static final boolean DEBUG = BuildConfig.DEBUG;
    private static final String TAG = "imkey";

    public static void d(String msg) {
        if (DEBUG)
            Log.d(TAG, msg);
    }

    public static void d(String tag, String msg) {
        if (DEBUG)
            Log.d(tag, msg);
    }

    public static void e(String msg){
        if(DEBUG)
            Log.e(TAG, msg);
    }

    public static void e(String tag, String msg) {
        if(DEBUG)
            Log.e(tag, msg);
    }
}
