package org.moa.android.crypto.coreapi;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/*
 * This class creates PBKDF2 with Hmac||SHA256/384/512 or SHA3-256/384/512.
 */
public class PBKDF2 {

    /**
     * kdfGen Method : hashFunction, password, salt, iteration, dkLen을 입력받아 dkLen 길이에 해당하는 DK 생성
     *
     * @param hashFunction - Hash Alg Name Input
     * @param password     - PSW Bytes Data Input
     * @param salt         - Salt Bytes Data Input
     * @param iterations   - Hmac Repeat Number Input
     * @param dkLen        - Derived key length
     * @return dk - dk Gen result Bytes return as dkLen
     */
    public static byte[] kdfGen(String hashFunction, byte[] password, byte[] salt, int iterations, int dkLen) {
        int hLen = 64;
        switch (hashFunction) {
            case "SHA3-256":
            case "SHA256":
                hLen = 32;
                break;
            case "SHA3-384":
            case "SHA384":
                hLen = 48;
                break;
            case "SHA3-512":
            case "SHA512":
                hLen = 64;
                break;
        }
        int l = (int) Math.ceil((double) dkLen / (double) hLen);
        byte[] dk = new byte[dkLen];
        for (int i = 1; i <= l; i++) {
            byte[] T = F(hashFunction, password, salt, iterations, i);
            for (int k = 0; k < T.length; k++) {
                if ((i - 1) * hLen + k < dk.length) dk[(i - 1) * hLen + k] = T[k];
            }
        }
        password[0] = (byte) 0x00;    // password delete in Memory
        salt[0] = (byte) 0x00;    // password delete in Memory
        return dk;
    }

    /**
     * F Method : HashFunction,Password, salt, iterationCount, index를 입력받아 축약한 바이트 정보 반환
     *
     * @param hashFunction - Hash Alg
     * @param password     - User Input Security Info
     * @param salt         - Random Number Info each User
     * @param iterations   - Repeat Count
     * @param index        - Hmac Block index
     * @return T - F Method Result Bytes
     */
    private static byte[] F(String hashFunction, byte[] password, byte[] salt, int iterations, int index) {
        byte[] saltConcatIndex = new byte[salt.length + 4];
        System.arraycopy(salt, 0, saltConcatIndex, 0, salt.length);
        byte[] iByteArray = ByteBuffer.allocate(4).putInt(index).array();
        System.arraycopy(iByteArray, 0, saltConcatIndex, salt.length, iByteArray.length);
        byte[] U = hmacPRF(hashFunction, password, saltConcatIndex);
        byte[] T = new byte[U.length];
        System.arraycopy(U, 0, T, 0, T.length);
        for (int c = 1; c < iterations; c++) {
            U = hmacPRF(hashFunction, password, U);
            for (int k = 0; k < U.length; k++) {
                T[k] = (byte) (((int) T[k]) ^ ((int) U[k]));
            }
        }
        return T;
    }


    /**
     * hmacPRF Method : HashFunction,key, mdTarget을 입력받아 축약한 바이트 정보 반환
     *
     * @param hashFunction - Hash Alg Name Input
     * @param key          - Hmac Key Input
     * @param mdTarget     - Hmac target data Input
     * @return resultPRF - hmacPRF Result Bytes return
     */
    private static byte[] hmacPRF(String hashFunction, byte[] key, byte[] mdTarget) {
        byte[] resultPRF = null;
        if (key.length == 0) key = new byte[]{0x00};
        try {
            Mac hmacSHAn = Mac.getInstance("Hmac" + hashFunction);
            hmacSHAn.init(new SecretKeySpec(key, "Hmac" + hashFunction));
            resultPRF = hmacSHAn.doFinal(mdTarget);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return resultPRF;
    }
}
