package org.moa.wallet.android.api;

import android.util.Log;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MoaCommon {
    private MoaCommon() {
    }

    public static MoaCommon getInstance() {
        return Singleton.instance;
    }

    public byte[] hashDigest(String algorithmName, byte[] targetData) {
        if (algorithmName == null) {
            Log.d("MoaLib", "algorithmName is null");
            return new byte[0];
        }
        if (targetData == null) {
            Log.d("MoaLib", "targetData is null");
            return new byte[0];
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    public byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        if (algorithmName == null) {
            Log.d("MoaLib", "algorithmName is null");
            return new byte[0];
        }
        if (targetData == null) {
            Log.d("MoaLib", "targetData is null");
            return new byte[0];
        }
        if (key == null) {
            Log.d("MoaLib", "key is null");
            return new byte[0];
        }
        try {
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(new SecretKeySpec(key, algorithmName));
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static class Singleton {
        private static MoaCommon instance = new MoaCommon();
    }
}
