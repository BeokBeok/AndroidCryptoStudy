package org.moa.auth.userauth.manager;

import android.content.Context;
import android.util.Base64;

import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.auth.userauth.android.api.MoaConfigurable;

import java.security.KeyStore;

abstract class PINAuth implements MoaConfigurable {
    Context context;
    String uniqueDeviceID;
    KeyStore keyStore;
    SymmetricCrypto symmetricCrypto;

    public void init(Context context, String uniqueDeviceID) {
        boolean isContext = (this.context != null);
        boolean isUniqueDeviceID = (this.uniqueDeviceID != null && this.uniqueDeviceID.length() > 0);
        if (isContext && isUniqueDeviceID)
            return;

        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
        setSymmetricCryptoInstance();
    }

    private void setSymmetricCryptoInstance() {
        if (symmetricCrypto != null)
            return;
        String transformation = "AES/CBC/PKCS7Padding";
        byte[] src = Base64.decode(uniqueDeviceID, Base64.NO_WRAP);
        byte[] key = new byte[32];
        System.arraycopy(src, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(src, key.length - 1, iv, 0, iv.length);
        symmetricCrypto = new SymmetricCrypto(transformation, iv, key);
    }
}
