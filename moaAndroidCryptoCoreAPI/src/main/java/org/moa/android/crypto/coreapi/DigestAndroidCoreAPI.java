package org.moa.android.crypto.coreapi;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DigestAndroidCoreAPI {

    public static synchronized byte[] hashDigest(String algorithmName, byte[] dataBytes) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(dataBytes);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(algorithmName + " not found", e);
        }
    }

    public static synchronized byte[] hmacDigest(String algorithmName, byte[] dataByte, byte[] hmacKeyByte) {
        try {
            final SecretKeySpec hmacKey = new SecretKeySpec(hmacKeyByte, algorithmName);
            Mac hmac = Mac.getInstance(algorithmName);
            hmac.init(hmacKey);
            hmac.update(dataByte);
            return hmac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(algorithmName + " not found", e);
        }
    }
}
