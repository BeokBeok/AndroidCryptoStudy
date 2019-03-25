package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

public class AuthToken implements MoaTEEKeyStore, MoaPreferences {
    private final String keyAlias = MoaTEEKeyStore.ALIAS_AUTH_TOKEN;
    private final String FORMAT_ENCODE = "UTF-8";
    private final String transformation = "AES/GCM/NoPadding";
    private Context context;
    private KeyStore keyStore;

    @RequiresApi(api = Build.VERSION_CODES.M)
    private AuthToken() {
        initKeyStore();
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[AuthToken] failed to check key alias");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public static AuthToken getInstance() {
        return Singleton.instance;
    }

    public void init(Context context) {
        this.context = context;
    }

    @Override
    public void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(MoaTEEKeyStore.PROVIDER);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[AuthToken][initKeyStore] failed to init keystore");
            throw new RuntimeException("Failed to init keystore", e);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, MoaTEEKeyStore.PROVIDER);
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(10)
                            .build()
            );
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[AuthToken][generateKey] failed to generate key");
            throw new RuntimeException("Failed to generate key", e);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void setValuesInPreferences(String key, String value) {
        String encryptedData = getEncryptContent(value);
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_AUTH_TOKEN, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encryptedData);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_AUTH_TOKEN, Context.MODE_PRIVATE);
        byte[] encryptData = Base64.decode(pref.getString(key, ""), Base64.NO_WRAP);
        return getDecryptContent(encryptData);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private String getEncryptContent(String content) {
        String resultData;
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();

            KeyStore.SecretKeyEntry secretKeyEntry = ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null));
            if (secretKeyEntry == null) {
                Log.d("MoaLib", "[AuthToken][getEncryptContent] secret key is null");
                return null;
            }
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyEntry.getSecretKey());
            resultData = Base64.encodeToString(cipher.doFinal(content.getBytes(FORMAT_ENCODE)), Base64.NO_WRAP);

            setIV(cipher.getIV());
        } catch (InvalidKeyException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException
                | NoSuchPaddingException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
            Log.d("MoaLib", "[AuthToken][getEncryptContent] failed to get encrypted content");
            throw new RuntimeException("Failed to get encrypted content", e);
        }
        return resultData;
    }

    private String getDecryptContent(byte[] content) {
        String result;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null);
            if (secretKeyEntry == null) {
                Log.d("MoaLib", "[AuthToken][getDecryptContent] secretKeyEntry is null");
                return null;
            }

            cipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.getSecretKey(), new GCMParameterSpec(128, getIV()));
            byte[] decryptData = cipher.doFinal(content);
            result = new String(decryptData, FORMAT_ENCODE);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException |
                KeyStoreException | UnrecoverableEntryException | IllegalBlockSizeException | BadPaddingException |
                UnsupportedEncodingException e) {
            Log.d("MoaLib", "[AuthToken][getDecryptContent] failed to get decrypt content");
            throw new RuntimeException("Failed to get decrypt content", e);
        }
        return result;
    }

    private byte[] getIV() {
        SharedPreferences pref = context.getSharedPreferences("IV_AuthToken", Context.MODE_PRIVATE);
        return Base64.decode(pref.getString("iv", ""), Base64.NO_WRAP);
    }

    private void setIV(byte[] iv) {
        SharedPreferences pref = context.getSharedPreferences("IV_AuthToken", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("iv", Base64.encodeToString(iv, Base64.NO_WRAP));
        editor.apply();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final AuthToken instance = new AuthToken();
    }

}
