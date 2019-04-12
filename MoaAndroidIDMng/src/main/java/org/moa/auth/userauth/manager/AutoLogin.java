package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.android.api.MoaCommonFunc;
import org.moa.auth.userauth.android.api.MoaMember;
import org.moa.auth.userauth.android.api.MoaPreferences;
import org.moa.auth.userauth.android.api.MoaTEEKeyStore;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.x500.X500Principal;

public class AutoLogin extends PINAuth implements MoaTEEKeyStore, MoaCommonFunc {
    private final int iterationCount = 8192;
    private final int keySize = 192;
    private final String secretKeyAlgorithm = "PBEwithSHAAND3-KEYTRIPLEDES-CBC";
    private final String keyAlias = MoaTEEKeyStore.ALIAS_AUTO_INFO;
    private final String transformationRSA = "RSA/ECB/PKCS1Padding";

    private AutoLogin() {
        initKeyStore();
    }

    public static AutoLogin getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[AutoLogin] failed to check key alias");
        }
    }

    @Override
    public void initKeyStore() {
        try {
            super.keyStore = KeyStore.getInstance(MoaTEEKeyStore.PROVIDER);
            super.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[AutoLogin][initKeyStore] failed to init keystore");
            throw new RuntimeException("Failed to init keystore", e);
        }
    }

    @Override
    public void generateKey() {
        Calendar startData = Calendar.getInstance();
        Calendar endData = Calendar.getInstance();
        endData.add(Calendar.YEAR, 25);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", MoaTEEKeyStore.PROVIDER);
            keyPairGenerator.initialize(
                    new KeyPairGeneratorSpec.Builder(context)
                            .setAlias(keyAlias)
                            .setSerialNumber(BigInteger.ONE)
                            .setSubject(new X500Principal("CN=" + keyAlias))
                            .setStartDate(startData.getTime())
                            .setEndDate(endData.getTime())
                            .build()
            );
            keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[AutoLogin][generateKey] Failed to create auto login key pair");
            throw new RuntimeException("Failed to create auto login key pair", e);
        }
    }

    @Override
    public void setValuesInPreferences(String key, String value) {
        String encryptValue = "";
        if (key.equals(MoaPreferences.KEY_AUTO_LOGIN))
            encryptValue = getEncryptContent(value);
        else if (key.equals(MoaPreferences.KEY_AUTO_SALT)) {
            byte[] decode = Base64.decode(value, Base64.NO_WRAP);
            byte[] encryptSalt = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, decode);
            encryptValue = Base64.encodeToString(encryptSalt, Base64.NO_WRAP);
        }
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encryptValue);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (key.equals(MoaPreferences.KEY_AUTO_LOGIN))
            return getDecryptContent(value);
        else if (key.equals(MoaPreferences.KEY_AUTO_SALT)) {
            byte[] decode = Base64.decode(value, Base64.NO_WRAP);
            byte[] decrypt = symmetricCrypto.getSymmetricData(Cipher.DECRYPT_MODE, decode);
            return Base64.encodeToString(decrypt, Base64.NO_WRAP);
        }
        return "";
    }

    public void setAutoInfo(String password) {
        if (password == null) {
            // Hashing "MoaPlanet" (SHA-512)
            password = "42009FFDDE80CA527DE3E1AB330481F7A4D76C35A3E7F9571BBA626927A25720B13E2C3F4EDE02DB5BA7B71151F8C7FFA5E4D559B7E7FED75DCCF636276B962B";
        }
        String content = MoaMember.AutoLoginType.ACTIVE.getType() + "$" + password;
        setValuesInPreferences(MoaPreferences.KEY_AUTO_LOGIN, content);
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[64];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] getEncryptPBEContent(String content) {
        byte[] encryptContent;
        try {
            Cipher cipher = Cipher.getInstance(secretKeyAlgorithm);
            byte[] salt = generateSalt();
            byte[] hashUniqueDeviceID = hashDigest("SHA-512", (uniqueDeviceID + String.valueOf(iterationCount)).getBytes());
            KeySpec keySpec = new PBEKeySpec(new String(hashUniqueDeviceID, MoaCommonFunc.FORMAT_ENCODE).toCharArray(), salt, iterationCount, keySize);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, iterationCount);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
            encryptContent = cipher.doFinal(content.getBytes(MoaCommonFunc.FORMAT_ENCODE));

            String base64Salt = Base64.encodeToString(salt, Base64.NO_WRAP);
            setValuesInPreferences(MoaPreferences.KEY_AUTO_SALT, base64Salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
            Log.d("MoaLib", "[AutoLogin][getEncryptPBEContent] Failed to get PBE encrypt content");
            throw new RuntimeException("Failed to get PBE encrypt content", e);
        }
        return encryptContent;
    }

    private byte[] getDecryptPBEContent(byte[] content) {
        byte[] result;
        try {
            Cipher pbeCipher = Cipher.getInstance(secretKeyAlgorithm);
            String base64Salt = getValuesInPreferences(MoaPreferences.KEY_AUTO_SALT);
            byte[] salt = Base64.decode(base64Salt, Base64.NO_WRAP);
            byte[] hashUniqueDeviceID = hashDigest("SHA-512", (uniqueDeviceID + String.valueOf(iterationCount)).getBytes());
            KeySpec keySpec = new PBEKeySpec(new String(hashUniqueDeviceID, MoaCommonFunc.FORMAT_ENCODE).toCharArray(), salt, iterationCount, keySize);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, iterationCount);
            pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec);
            result = pbeCipher.doFinal(content);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException |
                InvalidKeyException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
            Log.d("MoaLib", "[AutoLogin][getDecryptPBEContent] Failed to get decrypt PBE content");
            throw new RuntimeException("Failed to get decrypt PBE content", e);
        }
        return result;
    }

    private byte[] getEncryptRSAContent(byte[] content) {
        byte[] resultData = {0,};
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            if (publicKey == null) {
                Log.d("MoaLib", "[AutoLogin][getEncryptRSAContent] publicKey key is null");
                return resultData;
            }
            Cipher cipher = Cipher.getInstance(transformationRSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            resultData = cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | KeyStoreException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            Log.d("MoaLib", "[AutoLogin][getEncryptRSAContent] failed to get encrypt RSA content");
            throw new RuntimeException("Failed to cipher init", e);
        }
        return resultData;
    }

    private byte[] getDecryptRSAContent(byte[] content) {
        byte[] result = {0,};
        try {
            Cipher cipher = Cipher.getInstance(transformationRSA);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            if (privateKey == null) {
                Log.d("MoaLib", "[AutoLogin][getDecryptRSAContent] private key is null");
                return result;
            }
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnrecoverableKeyException | KeyStoreException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            Log.d("MoaLib", "[AutoLogin][getDecryptRSAContent] failed to decrypt RSA content");
            throw new RuntimeException("Failed to decrypt RSA content", e);
        }
        return result;
    }

    private String getEncryptContent(String content) {
        byte[] firstEncrypt = getEncryptPBEContent(content);
        byte[] lastEncrypt = getEncryptRSAContent(firstEncrypt);
        return Base64.encodeToString(lastEncrypt, Base64.NO_WRAP);
    }

    private String getDecryptContent(String content) {
        byte[] decode = Base64.decode(content, Base64.NO_WRAP);
        byte[] firstDecrypt = getDecryptRSAContent(decode);
        byte[] lastDecrypt = getDecryptPBEContent(firstDecrypt);
        String original;
        try {
            original = new String(lastDecrypt, MoaCommonFunc.FORMAT_ENCODE);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[AutoLogin][getDecryptContent] failed to decrypt content");
            throw new RuntimeException("Failed to decrypt content", e);
        }
        return original;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final AutoLogin instance = new AutoLogin();
    }
}
