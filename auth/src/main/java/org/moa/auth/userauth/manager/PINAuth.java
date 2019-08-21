package org.moa.auth.userauth.manager;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.Symmetric;
import org.moa.auth.userauth.client.api.MoaClientMsgPacketLib;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

abstract class PINAuth {
    private static final String transformation = "AES/CBC/PKCS7Padding";
    private final byte[] iv = hexStringToByteArray("00FF0000FF00FF000000FFFF000000FF");

    Context context;
    String uid;
    KeyStore keyStore;
    Symmetric symmetric;

    void init(
            @NonNull Context context,
            @NonNull String uniqueDeviceID
    ) {
        this.context = context;
        this.uid = uniqueDeviceID;
        setSymmetricInstance();
    }

    /**
     * 회원 등록 시 서버에서 사용되는 메시지 생성
     *
     * @param id  아이디
     * @param psw 패스워드
     * @return ID || H[E(PW)] || HMAC(ID)
     */
    public String generateRegisterMessage(
            String id,
            String psw
    ) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        Symmetric symmetric = new Symmetric(
                transformation,
                iv,
                Arrays.copyOf(hashDigest(idBytes), iv.length) // Key
        );
        byte[] hashEncryptedPsw = hashDigest(
                symmetric.getSymmetricData(
                        Cipher.ENCRYPT_MODE,
                        psw.getBytes(StandardCharsets.UTF_8)
                )
        );
        byte[] hmacID = hmacDigest(
                idBytes,
                hashEncryptedPsw // Key
        );
        return Base64.encodeToString(
                MoaClientMsgPacketLib.IdPswRegistRequestMsgGen(
                        idBytes.length, idBytes,
                        hashEncryptedPsw.length, hashEncryptedPsw,
                        hmacID.length, hmacID
                ),
                Base64.NO_WRAP
        );
    }

    /**
     * 회원 로그인 시 서버에서 사용되는 메시지 생성
     *
     * @param id    아이디
     * @param psw   패스워드
     * @param nonce Nonce
     * @return ID || H[E(PW)] || HMAC(ID) || NONCE
     */
    public String generateLoginRequestMessage(
            String id,
            String psw,
            String nonce
    ) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        Symmetric symmetric = new Symmetric(
                transformation,
                iv,
                Arrays.copyOf(hashDigest(idBytes), iv.length) // Key
        );
        byte[] hashEncryptedPsw = hashDigest(
                symmetric.getSymmetricData( // Target
                        Cipher.ENCRYPT_MODE,
                        psw.getBytes(StandardCharsets.UTF_8)
                )
        );
        byte[] hmacID = hmacDigest(
                idBytes,
                hashEncryptedPsw // Key
        );
        byte[] nonceOTPBytes = hexStringToByteArray(nonce);
        return Base64.encodeToString(
                MoaClientMsgPacketLib.PinLogInRequestMsgGen(
                        idBytes.length, idBytes,
                        hashEncryptedPsw.length, hashEncryptedPsw,
                        hmacID.length, hmacID,
                        nonceOTPBytes.length, nonceOTPBytes
                ),
                Base64.NO_WRAP
        );
    }

    /**
     * 비밀번호 초기화 시 서버에서 사용되는 메시지 생성
     *
     * @param id       아이디
     * @param resetPsw 초기화 비밀번호
     * @return ID || H[E(PW)] || HMAC[H[E(PW)]]
     */
    public String generatePINResetRequestMessage(
            String id,
            String resetPsw
    ) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        String hashAndHmacPwMsg = generateHashAndHmacPswMsg(
                idBytes,
                resetPsw.getBytes(StandardCharsets.UTF_8)
        );
        StringTokenizer st = new StringTokenizer(hashAndHmacPwMsg, "$");
        byte[] hashEncryptedPsw = hexStringToByteArray(st.nextToken());
        byte[] hmacHashEncryptedPsw = hexStringToByteArray(st.nextToken());
        return Base64.encodeToString(
                MoaClientMsgPacketLib.PswReSetRequestMsgGen(
                        idBytes.length, idBytes,
                        hashEncryptedPsw.length, hashEncryptedPsw,
                        hmacHashEncryptedPsw.length, hmacHashEncryptedPsw
                ),
                Base64.NO_WRAP
        );
    }

    /**
     * 비밀번호 변경 시 서버에서 사용되는 메시지 생성
     *
     * @param id         아이디
     * @param currentPsw 현재 비밀번호
     * @param newPsw     새로운 비밀번호
     * @return ID || H[E(CurrentPW)] || HMAC[H[E(CurrentPW)]] || H[E(NewPW)] || HMAC[H[E(NewPW)]]
     */
    public String generatePINChangeRequestMessage(
            String id,
            String currentPsw,
            String newPsw
    ) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        String hashAndHmacCurrentPswMsg = generateHashAndHmacPswMsg(
                idBytes,
                currentPsw.getBytes(StandardCharsets.UTF_8)
        );
        StringTokenizer st = new StringTokenizer(hashAndHmacCurrentPswMsg, "$");
        byte[] hashEncryptedCurrentPsw = hexStringToByteArray(st.nextToken());
        byte[] HmacHashEncryptedCurrentPsw = hexStringToByteArray(st.nextToken());

        String hashAndHmacNewPswMsg = generateHashAndHmacPswMsg(
                idBytes,
                newPsw.getBytes(StandardCharsets.UTF_8)
        );
        st = new StringTokenizer(hashAndHmacNewPswMsg, "$");
        byte[] hashEncryptedNewPsw = hexStringToByteArray(st.nextToken());
        byte[] hmacHashEncryptedNewPsw = hexStringToByteArray(st.nextToken());
        return Base64.encodeToString(
                MoaClientMsgPacketLib.PswChangeRequestMsgGen(
                        idBytes.length, idBytes,
                        hashEncryptedCurrentPsw.length, hashEncryptedCurrentPsw,
                        HmacHashEncryptedCurrentPsw.length, HmacHashEncryptedCurrentPsw,
                        hashEncryptedNewPsw.length, hashEncryptedNewPsw,
                        hmacHashEncryptedNewPsw.length, hmacHashEncryptedNewPsw
                ),
                Base64.NO_WRAP
        );
    }

    private void setSymmetricInstance() {
        String transformation = "AES/CBC/PKCS7Padding";
        byte[] src = Base64.decode(uid, Base64.NO_WRAP);
        byte[] key = new byte[32];
        System.arraycopy(src, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(src, key.length - 1, iv, 0, iv.length);
        symmetric = new Symmetric(transformation, iv, key);
    }

    /**
     * 패스워드가 HASH 및 HMAC 된 메시지 생성
     *
     * @param id  아이디
     * @param psw 패스워드
     * @return H[E(PW)] || HMAC[H[E(PW)]]
     */
    private String generateHashAndHmacPswMsg(byte[] id, byte[] psw) {
        Symmetric symmetric = new Symmetric(
                transformation,
                iv,
                Arrays.copyOf(hashDigest(id), iv.length) // Key
        );
        byte[] hashEncryptedPsw = hashDigest(symmetric.getSymmetricData(Cipher.ENCRYPT_MODE, psw));
        byte[] hmacHashEncryptedPsw = hmacDigest(id, hashEncryptedPsw);

        return byteArrayToHexString(hashEncryptedPsw) + "$"
                + byteArrayToHexString(hmacHashEncryptedPsw);
    }

    private byte[] hashDigest(byte[] targetData) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
            messageDigest.update(targetData);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    private byte[] hmacDigest(byte[] targetData, byte[] key) {
        final String hmacAlg = "HmacSHA256";
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, hmacAlg);
            Mac mac = Mac.getInstance(hmacAlg);
            mac.init(secretKeySpec);
            mac.update(targetData);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
