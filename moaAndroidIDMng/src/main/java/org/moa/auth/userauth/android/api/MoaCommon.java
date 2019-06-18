package org.moa.auth.userauth.android.api;

import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.CryptoHelper;
import org.moa.auth.userauth.client.api.MoaClientMsgPacketLib;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MoaCommon {
    private static final String transformation = "AES/CBC/PKCS7Padding";
    private static final String hashAlg = "SHA256";
    private static final String hmacAlg = "HmacSHA256";
    private byte[] iv = hexStringToByteArray("00FF0000FF00FF000000FFFF000000FF");

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
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = new byte[iv.length];
        byte[] idBytesDigestM = hashDigest(hashAlg, idBytes);

        System.arraycopy(idBytesDigestM, 0, keyBytes, 0, iv.length);
        CryptoHelper.getInstance().initSymmetric(transformation, iv, keyBytes);
        byte[] encPswBytes = CryptoHelper.getInstance().getSymmetricData(Cipher.ENCRYPT_MODE, passwordBytes);
        byte[] pswDigestBytes = hashDigest(hashAlg, encPswBytes);
        byte[] idPswHmacDigestBytes = hmacDigest(hmacAlg, idBytes, pswDigestBytes);
        byte[] idPswRegistMsgGen = MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(idBytes.length, idBytes,
                pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes);
        return Base64.encodeToString(idPswRegistMsgGen, Base64.NO_WRAP);
    }

    String generateLoginRequestMessage(String id, String password, String nonceOTP) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = new byte[iv.length];
        byte[] idBytesDigestM = hashDigest(hashAlg, idBytes);

        System.arraycopy(idBytesDigestM, 0, keyBytes, 0, iv.length);
        CryptoHelper.getInstance().initSymmetric(transformation, iv, keyBytes);
        byte[] encPswBytes = CryptoHelper.getInstance().getSymmetricData(Cipher.ENCRYPT_MODE, passwordBytes);
        byte[] pswDigestBytes = hashDigest(hashAlg, encPswBytes);
        byte[] idPswHmacDigestBytes = hmacDigest(hmacAlg, idBytes, pswDigestBytes);
        byte[] nonceOTPBytes = hexStringToByteArray(nonceOTP);
        byte[] pinLoginRequestMsgGen = MoaClientMsgPacketLib.PinLogInRequestMsgGen(idBytes.length, idBytes,
                pswDigestBytes.length, pswDigestBytes, idPswHmacDigestBytes.length, idPswHmacDigestBytes,
                nonceOTPBytes.length, nonceOTPBytes);
        return Base64.encodeToString(pinLoginRequestMsgGen, Base64.NO_WRAP);
    }

    String generatePINResetRequestMessage(String androidMemberIdStr, String reSetPswStr) {
        byte[] idBytes = androidMemberIdStr.getBytes(StandardCharsets.UTF_8);
        byte[] passwordBytes = reSetPswStr.getBytes(StandardCharsets.UTF_8);

        String hashPswConcathmacPswStr = generateHashAndHmacPwMessage(idBytes, passwordBytes);
        StringTokenizer hashPswConcatHmacPswST = new StringTokenizer(hashPswConcathmacPswStr, "$");
        byte[] resetHashPswBytes = hexStringToByteArray(hashPswConcatHmacPswST.nextToken());
        byte[] resetHmacPswBytes = hexStringToByteArray(hashPswConcatHmacPswST.nextToken());

        byte[] pswReSetRequestMsgGenBytes = MoaClientMsgPacketLib.PswReSetRequestMsgGen(idBytes.length, idBytes, resetHashPswBytes.length, resetHashPswBytes, resetHmacPswBytes.length, resetHmacPswBytes);
        return Base64.encodeToString(pswReSetRequestMsgGenBytes, Base64.NO_WRAP);
    }

    String generatePINChangeRequestMessage(String androidMemberIdStr, String existPswStr, String changePswStr) {
        byte[] idBytes = androidMemberIdStr.getBytes(StandardCharsets.UTF_8);
        byte[] existPswBytes = existPswStr.getBytes(StandardCharsets.UTF_8);
        byte[] changePswBytes = changePswStr.getBytes(StandardCharsets.UTF_8);

        String existHashPswConcatHamcPswStr = generateHashAndHmacPwMessage(idBytes, existPswBytes);
        StringTokenizer existHashPswConcatHamcPswST = new StringTokenizer(existHashPswConcatHamcPswStr, "$");
        byte[] existHashPswBytes = hexStringToByteArray(existHashPswConcatHamcPswST.nextToken());
        byte[] existHmacPswBytes = hexStringToByteArray(existHashPswConcatHamcPswST.nextToken());

        String changeHashPswConcatHamcPswStr = generateHashAndHmacPwMessage(idBytes, changePswBytes);
        StringTokenizer changeHashPswConcatHamcPswST = new StringTokenizer(changeHashPswConcatHamcPswStr, "$");
        byte[] changeHashPswBytes = hexStringToByteArray(changeHashPswConcatHamcPswST.nextToken());
        byte[] changeHmacPswBytes = hexStringToByteArray(changeHashPswConcatHamcPswST.nextToken());

        byte[] pswChangeRequestMsgGenBytes = MoaClientMsgPacketLib.PswChangeRequestMsgGen(idBytes.length, idBytes, existHashPswBytes.length, existHashPswBytes, existHmacPswBytes.length, existHmacPswBytes, changeHashPswBytes.length, changeHashPswBytes, changeHmacPswBytes.length, changeHmacPswBytes);

        return Base64.encodeToString(pswChangeRequestMsgGenBytes, Base64.NO_WRAP);
    }

    private String generateHashAndHmacPwMessage(byte[] idBytes, byte[] passwordBytes) {
        byte[] keyBytes = new byte[iv.length];
        byte[] idHashBytes = hashDigest(hashAlg, idBytes);
        System.arraycopy(idHashBytes, 0, keyBytes, 0, iv.length);
        CryptoHelper.getInstance().initSymmetric(transformation, iv, keyBytes);
        byte[] encPswBytes = CryptoHelper.getInstance().getSymmetricData(Cipher.ENCRYPT_MODE, passwordBytes);

        byte[] hashPswBytes = hashDigest(hashAlg, encPswBytes);
        byte[] hmacPswBytes = hmacDigest(hmacAlg, idBytes, hashPswBytes);

        String hashPswHexStr = byteArrayToHexString(hashPswBytes);
        String hmacPswHexStr = byteArrayToHexString(hmacPswBytes);
        return hashPswHexStr + "$" + hmacPswHexStr;
    }

    private byte[] hashDigest(String algorithmName, byte[] targetData) {
        if (algorithmName == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "algorithmName is null");
            return new byte[0];
        }
        if (targetData == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "MoaLib is null");
            return new byte[0];
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(getClassAndMethodName() + e.getMessage());
        }
    }

    private byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
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
            throw new RuntimeException(getClassAndMethodName() + e.getMessage());
        }
    }

    private byte[] hexStringToByteArray(String s) {
        if (s == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "s is null");
            return new byte[0];
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "bytes is null");
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static class Singleton {
        private static final MoaCommon instance = new MoaCommon();
    }
}