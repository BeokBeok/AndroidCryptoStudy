package org.moa.auth.userauth.android.api;

import android.util.Base64;

import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.auth.userauth.client.api.MoaClientMsgPacketLib;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MoaCommon {
    private MoaCommon() {
    }

    public static MoaCommon getInstance() {
        return Singleton.instance;
    }

    public String getClassAndMethodName() {
        return "[" + Thread.currentThread().getStackTrace()[1].getClassName() + "]" +
                "[" + Thread.currentThread().getStackTrace()[1].getMethodName() + "]";
    }

    String generateRegisterMessage(String id, String password) {
        String transformation = "AES/CBC/PKCS7Padding";
        String hashAlg = "SHA256";
        String hmacAlg = "HmacSHA256";
        byte[] idPswRegistMsgGen;
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = hexStringToByteArray("00FF0000FF00FF000000FFFF000000FF");
        byte[] keyBytes = new byte[ivBytes.length];
        byte[] idBytesDigestM = hashDigest(hashAlg, idBytes);

        System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformation, ivBytes, keyBytes);
        byte[] encPswBytes = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, passwordBytes);
        byte[] pswDigestBytes = hashDigest(hashAlg, encPswBytes);
        byte[] idPswHmacDigestBytes = hmacDigest(hmacAlg, idBytes, pswDigestBytes);
        idPswRegistMsgGen = MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(idBytes.length, idBytes,
                pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes);
        return Base64.encodeToString(idPswRegistMsgGen, Base64.NO_WRAP);
    }

    String generateLoginRequestMessage(String id, String password, String nonceOTP) {
        String transformation = "AES/CBC/PKCS7Padding";
        String hashAlg = "SHA256";
        String hmacAlg = "HmacSHA256";
        byte[] pinLoginRequestMsgGen;
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = hexStringToByteArray("00FF0000FF00FF000000FFFF000000FF");
        byte[] keyBytes = new byte[ivBytes.length];
        byte[] idBytesDigestM = hashDigest(hashAlg, idBytes);

        System.arraycopy(idBytesDigestM, 0, keyBytes, 0, ivBytes.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformation, ivBytes, keyBytes);
        byte[] encPswBytes = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, passwordBytes);
        byte[] pswDigestBytes = hashDigest(hashAlg, encPswBytes);
        byte[] idPswHmacDigestBytes = hmacDigest(hmacAlg, idBytes, pswDigestBytes);
        byte[] nonceOTPBytes = hexStringToByteArray(nonceOTP);
        pinLoginRequestMsgGen = MoaClientMsgPacketLib.PinLogInRequestMsgGen(idBytes.length, idBytes,
                pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes,
                nonceOTPBytes.length, nonceOTPBytes);
        return Base64.encodeToString(pinLoginRequestMsgGen, Base64.NO_WRAP);
    }

    private byte[] hashDigest(String algorithmName, byte[] targetData) {
        if (algorithmName == null || targetData == null)
            return new byte[0];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(getClassAndMethodName() + e.getMessage());
        }
    }

    private byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        if (algorithmName == null || targetData == null || key == null)
            return new byte[0];
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithmName);
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKeySpec);
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(getClassAndMethodName() + e.getMessage());
        }
    }

    private byte[] hexStringToByteArray(String s) {
        if (s == null)
            return new byte[0];
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static class Singleton {
        private static final MoaCommon instance = new MoaCommon();
    }
}