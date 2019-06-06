package org.moa.wallet.android.api;

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
        if (algorithmName == null || targetData == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "AlgorithmName or targetData is null");
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to hash", e);
        }
    }

    public byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        if (algorithmName == null || targetData == null || key == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "AlgorithmName or targetData or key is null");
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithmName);
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKeySpec);
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to hmac", e);
        }
    }

    private static class Singleton {
        private static MoaCommon instance = new MoaCommon();
    }
}
