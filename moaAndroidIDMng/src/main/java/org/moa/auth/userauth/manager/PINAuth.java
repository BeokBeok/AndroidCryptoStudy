package org.moa.auth.userauth.manager;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.Symmetric;
import org.moa.auth.userauth.android.api.MoaCommon;

import java.security.KeyStore;

abstract class PINAuth {
    Context context;
    String uniqueDeviceID;
    KeyStore keyStore;
    Symmetric symmetric;

    public void init(Context context, String uniqueDeviceID) {
        if (context == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "context is null");
            return;
        }
        if (uniqueDeviceID == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "uniqueDeviceID is null");
            return;
        }
        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
        setSymmetricInstance();
    }

    private void setSymmetricInstance() {
        String transformation = "AES/CBC/PKCS7Padding";
        byte[] src = Base64.decode(uniqueDeviceID, Base64.NO_WRAP);
        byte[] key = new byte[32];
        System.arraycopy(src, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(src, key.length - 1, iv, 0, iv.length);
        symmetric = new Symmetric(transformation, iv, key);
    }
}
