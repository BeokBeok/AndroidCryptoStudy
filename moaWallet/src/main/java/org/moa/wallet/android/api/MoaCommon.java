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

    public String getClassAndMethodName() {
        return "[" + Thread.currentThread().getStackTrace()[1].getClassName() + "]" +
                "[" + Thread.currentThread().getStackTrace()[1].getMethodName() + "]";
    }

    public byte[] hashDigest(String algorithmName, byte[] targetData) {
        if (algorithmName == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "algorithmName is null");
            return new byte[0];
        }
        if (targetData == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "targetData is null");
            return new byte[0];
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
        }
        return new byte[0];
    }

    public byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        if (algorithmName == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "algorithmName is null");
            return new byte[0];
        }
        if (targetData == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "targetData is null");
            return new byte[0];
        }
        if (key == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "key is null");
            return new byte[0];
        }
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithmName);
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKeySpec);
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
        }
        return new byte[0];
    }

    private static class Singleton {
        private static MoaCommon instance = new MoaCommon();
    }
}
