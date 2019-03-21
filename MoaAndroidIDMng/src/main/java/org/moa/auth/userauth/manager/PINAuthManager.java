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

abstract class PINAuthManager implements SharedPreferencesManager {
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

    public String generateOrGetRegisterMessage(String id, String password) {
        byte[] idPswRegistMsgGen;
        try {
            String algorithmName = "SHA256";
            String hmacAlgorithmName = "HmacSHA256";
            String transformation = "AES/CBC/PKCS7Padding";
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode("00FF0000FF00FF000000FFFF000000FF");
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = DigestAndroidCoreAPI.hashDigest(algorithmName, idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricAndroidCoreAPI symmetricAndroidCoreAPI = new SymmetricAndroidCoreAPI(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricAndroidCoreAPI.symmetricEncryptData(passwordBytes);
            byte[] pswDigestBytes = DigestAndroidCoreAPI.hashDigest(algorithmName, encPswBytes);
            byte[] idPswHmacDigestBytes = DigestAndroidCoreAPI.hmacDigest(hmacAlgorithmName, idBytes, pswDigestBytes);
            idPswRegistMsgGen = MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[PINAuthManager][generateOrGetRegisterMessage] failed to generate PIN register message");
            throw new RuntimeException("Failed to generate PIN register message", e);
        }
        return Base64.encodeToString(idPswRegistMsgGen, Base64.NO_WRAP);
    }

    public String generateOrGetLoginRequestMessage(String id, String password, String nonceOTP) {
        byte[] pinLoginRequestMsgGen;
        try {
            String algorithmName = "SHA256";
            String hmacAlgorithmName = "HmacSHA256";
            String transformation = "AES/CBC/PKCS7Padding";
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode("00FF0000FF00FF000000FFFF000000FF");
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = DigestAndroidCoreAPI.hashDigest(algorithmName, idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricAndroidCoreAPI symmetricAndroidCoreAPI = new SymmetricAndroidCoreAPI(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricAndroidCoreAPI.symmetricEncryptData(passwordBytes);
            byte[] pswDigestBytes = DigestAndroidCoreAPI.hashDigest(algorithmName, encPswBytes);
            byte[] idPswHmacDigestBytes = DigestAndroidCoreAPI.hmacDigest(hmacAlgorithmName, idBytes, pswDigestBytes);
            byte[] nonceOTPBytes = Hex.decode(nonceOTP);
            pinLoginRequestMsgGen = MoaClientMsgPacketLib.PinLogInRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes,
                    nonceOTPBytes.length, nonceOTPBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[PINAuthManager][generateOrGetLoginRequestMessage] failed to generate PIN login request message");
            throw new RuntimeException("Failed to generate PIN login request message", e);
        }
        return Base64.encodeToString(pinLoginRequestMsgGen, Base64.NO_WRAP);
    }
}
