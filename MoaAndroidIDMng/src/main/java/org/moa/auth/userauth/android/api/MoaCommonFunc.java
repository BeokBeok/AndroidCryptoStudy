package org.moa.auth.userauth.android.api;

import android.util.Base64;
import android.util.Log;

import org.bouncycastle.util.encoders.Hex;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.auth.userauth.client.api.MoaClientMsgPacketLib;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public interface MoaCommonFunc {
    String transformation = "AES/CBC/PKCS7Padding";
    String FORMAT_ENCODE = "UTF-8";

    default byte[] hashDigest(String algorithmName, byte[] targetData) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(algorithmName + " not found", e);
        }
    }

    default byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithmName);
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKeySpec);
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(algorithmName + " not found", e);
        }
    }

    default String generateRegisterMessage(String id, String password) {
        byte[] idPswRegistMsgGen;
        try {
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode("00FF0000FF00FF000000FFFF000000FF");
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = hashDigest("SHA256", idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricCrypto.encryptData(passwordBytes);
            byte[] pswDigestBytes = hashDigest("SHA256", encPswBytes);
            byte[] idPswHmacDigestBytes = hmacDigest("HmacSHA256", idBytes, pswDigestBytes);
            idPswRegistMsgGen = MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[generateRegisterMessage] failed to generate PIN register message");
            throw new RuntimeException("Failed to generate PIN register message", e);
        }
        return Base64.encodeToString(idPswRegistMsgGen, Base64.NO_WRAP);
    }

    default String generateLoginRequestMessage(String id, String password, String nonceOTP) {
        byte[] pinLoginRequestMsgGen;
        try {
            byte[] idBytes = id.getBytes(FORMAT_ENCODE);
            byte[] passwordBytes = password.getBytes(FORMAT_ENCODE);
            byte[] ivBytes = Hex.decode("00FF0000FF00FF000000FFFF000000FF");
            byte[] keyBytes = new byte[ivBytes.length];
            byte[] idBytesDigestM = hashDigest("SHA256", idBytes);

            System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
            SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformation, ivBytes, keyBytes);
            byte[] encPswBytes = symmetricCrypto.encryptData(passwordBytes);
            byte[] pswDigestBytes = hashDigest("SHA256", encPswBytes);
            byte[] idPswHmacDigestBytes = hmacDigest("HmacSHA256", idBytes, pswDigestBytes);
            byte[] nonceOTPBytes = Hex.decode(nonceOTP);
            pinLoginRequestMsgGen = MoaClientMsgPacketLib.PinLogInRequestMsgGen(idBytes.length, idBytes,
                    pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes,
                    nonceOTPBytes.length, nonceOTPBytes);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[generateLoginRequestMessage] failed to generate PIN login request message");
            throw new RuntimeException("Failed to generate PIN login request message", e);
        }
        return Base64.encodeToString(pinLoginRequestMsgGen, Base64.NO_WRAP);
    }
}
