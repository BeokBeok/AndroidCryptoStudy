package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.PBKDF2;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.auth.userauth.android.api.MoaCommonable;
import org.moa.auth.userauth.android.api.MoaConfigurable;
import org.moa.auth.userauth.android.api.MoaMember;
import org.moa.auth.userauth.android.api.MoaTEEUsable;

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
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

public class AutoLogin extends PINAuth implements MoaTEEUsable, MoaCommonable {
    private final String keyAlias = MoaTEEUsable.ALIAS_AUTO_INFO;
    private PBKDF2 pbkdf2;

    private AutoLogin() {
        initKeyStore();
        pbkdf2 = new PBKDF2("SHA384");
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
            super.keyStore = KeyStore.getInstance(MoaTEEUsable.PROVIDER);
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
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", MoaTEEUsable.PROVIDER);
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
        if (key.equals(MoaConfigurable.KEY_AUTO_LOGIN))
            encryptValue = getEncryptContent(value);
        else if (key.equals(MoaConfigurable.KEY_AUTO_SALT)) {
            byte[] decode = Base64.decode(value, Base64.NO_WRAP);
            byte[] encryptSalt = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, decode);
            encryptValue = Base64.encodeToString(encryptSalt, Base64.NO_WRAP);
        }
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encryptValue);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            return "";
        if (key.equals(MoaConfigurable.KEY_AUTO_LOGIN))
            return getDecryptContent(value);
        else if (key.equals(MoaConfigurable.KEY_AUTO_SALT)) {
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
        setValuesInPreferences(MoaConfigurable.KEY_AUTO_LOGIN, content);
    }

    private byte[] getSalt() {
        String base64Salt = getValuesInPreferences(MoaConfigurable.KEY_AUTO_SALT);
        if (base64Salt == null || base64Salt.length() == 0) {
            byte[] salt = new byte[64];
            new SecureRandom().nextBytes(salt);
            setValuesInPreferences(MoaConfigurable.KEY_AUTO_SALT, Base64.encodeToString(salt, Base64.NO_WRAP));
            return salt;
        } else
            return Base64.decode(base64Salt, Base64.NO_WRAP);
    }

    private byte[] getPBKDF2Data(int encOrDecMode, byte[] data) {
        byte[] resultData = {0,};
        byte[] derivedKey = generateDerivedKey();
        if (derivedKey.length != 48)
            return resultData;

        String transformationAES = "AES/CBC/PKCS7Padding";
        byte[] key = new byte[32];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformationAES, iv, key);
        resultData = symmetricCrypto.getSymmetricData(encOrDecMode, data);
        return resultData;
    }

    private byte[] generateDerivedKey() {
        int iterationCount = 8192;
        int keySize = 48;
        byte[] salt = getSalt();
        byte[] pw = Base64.decode(uniqueDeviceID, Base64.NO_WRAP);
        return pbkdf2.kdfGen(pw, salt, iterationCount, keySize);
    }

    private byte[] getRSAData(int encOrDecMode, byte[] data) {
        byte[] resultData = {0,};
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
            String transformationRSA = "RSA/ECB/PKCS1Padding";
            Cipher cipher = Cipher.getInstance(transformationRSA);
            if (encOrDecMode == Cipher.ENCRYPT_MODE) {
                PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
                if (publicKey == null) {
                    Log.d("MoaLib", "[AutoLogin][getRSAData] public key is null");
                    return resultData;
                }
                cipher.init(encOrDecMode, publicKey);
            } else if (encOrDecMode == Cipher.DECRYPT_MODE) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                if (privateKey == null) {
                    Log.d("MoaLib", "[AutoLogin][getRSAData] private key is null");
                    return resultData;
                }
                cipher.init(encOrDecMode, privateKey);
            }
            resultData = cipher.doFinal(data);
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException | UnrecoverableKeyException e) {
            Log.d("MoaLib", "[AutoLogin][getRSAData] failed to get RSA data");
        }
        return resultData;
    }

    private String getEncryptContent(String content) {
        String encryptedData = "";
        int cipherMode = Cipher.ENCRYPT_MODE;
        try {
            byte[] encode = content.getBytes(MoaCommonable.FORMAT_ENCODE);
            byte[] firstEncrypt = getPBKDF2Data(cipherMode, encode);
            byte[] lastEncrypt = getRSAData(cipherMode, firstEncrypt);
            encryptedData = Base64.encodeToString(lastEncrypt, Base64.NO_WRAP);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[AutoLogin][getEncryptContent] occurred UnsupportedEncodingException");
        }
        return encryptedData;
    }

    private String getDecryptContent(String content) {
        String decryptedData = "";
        int cipherMode = Cipher.DECRYPT_MODE;
        try {
            byte[] decode = Base64.decode(content, Base64.NO_WRAP);
            byte[] firstDecrypt = getRSAData(cipherMode, decode);
            byte[] lastDecrypt = getPBKDF2Data(cipherMode, firstDecrypt);
            decryptedData = new String(lastDecrypt, MoaCommonable.FORMAT_ENCODE);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[AutoLogin][getDecryptContent] occurred UnsupportedEncodingException");
        }
        return decryptedData;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final AutoLogin instance = new AutoLogin();
    }
}
