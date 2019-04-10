package org.moa.auth.userauth.manager;

import android.content.Context;

import org.moa.auth.userauth.android.api.MoaPreferences;

import java.security.KeyStore;

abstract class PINAuth implements MoaPreferences {
    Context context;
    String uniqueDeviceID;
    KeyStore keyStore;

    public void init(Context context, String uniqueDeviceID) {
        boolean isContext = (this.context != null);
        boolean isUniqueDeviceID = (this.uniqueDeviceID != null && this.uniqueDeviceID.length() > 0);
        if (isContext && isUniqueDeviceID)
            return;

        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
    }
}
