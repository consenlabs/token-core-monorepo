package im.imkey.imkeylibrary.utils;

import android.util.Log;

import im.imkey.imkeylibrary.BuildConfig;

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
