package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import org.moa.auth.userauth.android.api.MoaCommon;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

public class AuthToken {
    private final String keyAlias = "MoaUserAuthToken";
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
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to check key alias");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public static AuthToken getInstance() {
        return Singleton.instance;
    }

    public void init(Context context) {
        this.context = context;
    }

    public String get() {
        SharedPreferences pref = context.getSharedPreferences("androidAuthToken", Context.MODE_PRIVATE);
        byte[] encryptData = Base64.decode(pref.getString("AuthToken.Info", ""), Base64.NO_WRAP);
        return getDecryptContent(encryptData);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void set(String value) {
        if (value == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Value is null");
        String encryptedData = getEncryptContent(value);
        SharedPreferences pref = context.getSharedPreferences("androidAuthToken", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("AuthToken.Info", encryptedData);
        editor.apply();
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance("AndroidKeyStore");
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to init keystore");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
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
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to generate key");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private String getEncryptContent(String content) {
        if (content == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Content is null");
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();

            KeyStore.SecretKeyEntry secretKeyEntry = ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null));
            if (secretKeyEntry == null)
                throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Secret key is null");
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyEntry.getSecretKey());
            setIV(cipher.getIV());
            return Base64.encodeToString(cipher.doFinal(content.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
        } catch (InvalidKeyException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException
                | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to get encrypted content");
        }
    }

    private String getDecryptContent(byte[] content) {
        if (content == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Content is null");
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null);
            if (secretKeyEntry == null)
                throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "SecretKeyEntry is null");
            cipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.getSecretKey(), new GCMParameterSpec(128, getIV()));
            byte[] decryptData = cipher.doFinal(content);
            return new String(decryptData, StandardCharsets.UTF_8);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException |
                KeyStoreException | UnrecoverableEntryException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to get decrypt content");
        }
    }

    private byte[] getIV() {
        SharedPreferences pref = context.getSharedPreferences("IV_AuthToken", Context.MODE_PRIVATE);
        return Base64.decode(pref.getString("iv", ""), Base64.NO_WRAP);
    }

    private void setIV(byte[] iv) {
        if (iv == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Iv is null");
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
