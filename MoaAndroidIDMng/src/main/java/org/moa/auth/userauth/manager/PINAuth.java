package org.moa.auth.userauth.manager;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.util.encoders.Hex;
import org.moa.android.crypto.coreapi.DigestAndroidCoreAPI;
import org.moa.android.crypto.coreapi.SymmetricAndroidCoreAPI;
import org.moa.auth.userauth.client.api.MoaClientMsgPacketLib;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;

abstract class PINAuth implements MoaPreferences {
    private final String transformation = "AES/CBC/PKCS7Padding";
    private final String iv = "00FF0000FF00FF000000FFFF000000FF";
    final String FORMAT_ENCODE = "UTF-8";
    Context context;
    String uniqueDeviceID;
    KeyStore keyStore;

    void init(Context context, String uniqueDeviceID) {
        boolean isContext = (this.context != null);
        boolean isUniqueDeviceID = (this.uniqueDeviceID != null && this.uniqueDeviceID.length() > 0);
        if (isContext && isUniqueDeviceID)
            return;

        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
    }

    public String generateRegisterMessage(String id, String password) {
        byte[] idPswRegistMsgGen;
        try {
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode(iv);
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = DigestAndroidCoreAPI.hashDigest("SHA256", idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricAndroidCoreAPI symmetricAndroidCoreAPI = new SymmetricAndroidCoreAPI(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricAndroidCoreAPI.symmetricEncryptData(passwordBytes);
            byte[] pswDigestBytes = DigestAndroidCoreAPI.hashDigest("SHA256", encPswBytes);
            byte[] idPswHmacDigestBytes = DigestAndroidCoreAPI.hmacDigest("HmacSHA256", idBytes, pswDigestBytes);
            idPswRegistMsgGen = MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[PINAuth][generateRegisterMessage] failed to generate PIN register message");
            throw new RuntimeException("Failed to generate PIN register message", e);
        }
        return Base64.encodeToString(idPswRegistMsgGen, Base64.NO_WRAP);
    }

    public String generateLoginRequestMessage(String id, String password, String nonceOTP) {
        byte[] pinLoginRequestMsgGen;
        try {
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode(iv);
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = DigestAndroidCoreAPI.hashDigest("SHA256", idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricAndroidCoreAPI symmetricAndroidCoreAPI = new SymmetricAndroidCoreAPI(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricAndroidCoreAPI.symmetricEncryptData(passwordBytes);
            byte[] pswDigestBytes = DigestAndroidCoreAPI.hashDigest("SHA256", encPswBytes);
            byte[] idPswHmacDigestBytes = DigestAndroidCoreAPI.hmacDigest("HmacSHA256", idBytes, pswDigestBytes);
            byte[] nonceOTPBytes = Hex.decode(nonceOTP);
            pinLoginRequestMsgGen = MoaClientMsgPacketLib.PinLogInRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes,
                    nonceOTPBytes.length, nonceOTPBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[PINAuth][generateLoginRequestMessage] failed to generate PIN login request message");
            throw new RuntimeException("Failed to generate PIN login request message", e);
        }
        return Base64.encodeToString(pinLoginRequestMsgGen, Base64.NO_WRAP);
    }
}
