package org.moa.auth.userauth.android.api;

import android.util.Log;

public class MoaDebugLogger {
    private static final String TAG = "MoaLib";

    public static final void w(String message) {
        if (BuildConfig.DEBUG)
            Log.w(TAG, message);
    }

    public static final void i(String message) {
        if (BuildConfig.DEBUG)
            Log.i(TAG, message);
    }

    public static final void d(String message) {
        if (BuildConfig.DEBUG)
            Log.d(TAG, message);
    }

    public static final void v(String message) {
        if (BuildConfig.DEBUG)
            Log.v(TAG, message);
    }
}
