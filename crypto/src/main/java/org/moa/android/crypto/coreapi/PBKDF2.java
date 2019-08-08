package org.moa.android.crypto.coreapi;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/*
 * This class creates PBKDF2 with Hmac||SHA256/384/512 or SHA3-256/384/512.
 */
public class PBKDF2 {
    private Mac hmacSHAn;
    private final String hashAlg;
    private int hLen = 64;

    public PBKDF2(String hashAlg) {
        this.hashAlg = hashAlg;                            // SHA Alg Declaration
        try {
            hmacSHAn = Mac.getInstance("Hmac" + hashAlg);    // HmacSHAn Instance Gen
        } catch (NoSuchAlgorithmException e) {
            Log.d("MoaLib", "[PBKDF2]" + e.getMessage());
            return;
        }

        switch (hashAlg) {
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
    }

    /**
     * kdfGen Method : hashFunction, password, salt, iteration, dklen
     *
     * @param password   - PSW Bytes Data Input
     * @param salt       - Salt Bytes Data Input
     * @param iterations - Hmac Repeat Number Input
     * @return dk - dk Gen result Bytes return as dkLen
     */
    public byte[] kdfGen(byte[] password, byte[] salt, int iterations, int dkLen) {

        if (password.length == 0) password = new byte[]{0x00};
        try {
            hmacSHAn.init(new SecretKeySpec(password, "Hmac" + hashAlg));    // Only Perform one Hmac initialization(Speed Up)
        } catch (InvalidKeyException e) {
            Log.d("MoaLib", "[PBKDF2][kdfGen]" + e.getMessage());
            return new byte[0];
        }

        int l = (int) Math.ceil((double) dkLen / (double) hLen);
        byte[] dk = new byte[dkLen];
        for (int i = 1; i <= l; i++) {
            byte[] T = F(salt, iterations, i);    // byte[] T = F(hashAlg, password, salt, iterations, i) -> byte[] T = F(password, salt, iterations, i)
            for (int k = 0; k < T.length; k++) {
                if ((i - 1) * hLen + k < dk.length) dk[(i - 1) * hLen + k] = T[k];
            }
        }
        return dk;
    }

    /**
     * F Method : HashFunction,Password, salt, iterationCount, index
     *
     * @param salt       - Random Number Info each User
     * @param iterations - Repeat Count
     * @param index      - Hmac Block index
     * @return T - F Method Result Bytes
     */
    private byte[] F(byte[] salt, int iterations, int index) {
        byte[] saltConcatIndex = ByteBuffer.allocate(salt.length + 4).put(salt).putInt(index).array();
        byte[] U = hmacPRF(saltConcatIndex);    // byte[] U = hmacPRF(hashAlg, password, saltConcatIndex) -> byte[] U = hmacPRF(saltConcatIndex)
        byte[] T = Arrays.copyOf(U, U.length);
        for (int c = 1; c < iterations; c++) {
            U = hmacPRF(U);                    // U = hmacPRF(hashAlg, password, U) -> U = hmacPRF(U)
            for (int k = 0; k < U.length; k++) {
                T[k] = (byte) (((int) T[k]) ^ ((int) U[k]));
            }
        }
        return T;
    }

    private byte[] hmacPRF(byte[] mdTarget) {
        return hmacSHAn.doFinal(mdTarget);    // Only Perform Integrity Operations(Speed Up)
    }
}