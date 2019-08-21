package org.moa.auth.userauth.manager;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

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

@RequiresApi(api = Build.VERSION_CODES.M)
public class AuthToken {
    private final String keyAlias = "MoaUserAuthToken";
    private final String transformation = "AES/GCM/NoPadding";
    private Context context;
    private KeyStore keyStore;

    public AuthToken(@NonNull Context context) {
        this.context = context;
        initKeyStore();
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
        } catch (KeyStoreException e) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    public String get() {
        SharedPreferences pref =
                context.getSharedPreferences("androidAuthToken", Context.MODE_PRIVATE);
        byte[] encryptData = Base64.decode(
                pref.getString("AuthToken.Info", ""),
                Base64.NO_WRAP
        );
        return getDecryptContent(encryptData);
    }

    public void set(String value) {
        String encryptedData = getEncryptContent(value);
        SharedPreferences pref = context.getSharedPreferences(
                "androidAuthToken", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("AuthToken.Info", encryptedData);
        editor.apply();
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance("AndroidKeyStore");
            this.keyStore.load(null);
        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore"
            );
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(
                            keyAlias,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
                    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(10)
                            .build()
            );
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException |
                InvalidAlgorithmParameterException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private String getEncryptContent(String content) {
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
            KeyStore.SecretKeyEntry secretKeyEntry =
                    ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null));
            if (secretKeyEntry == null) {
                Log.d("MoaLib", "Secret key is null");
                return "";
            }
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyEntry.getSecretKey());
            setIV(cipher.getIV());
            return Base64.encodeToString(
                    cipher.doFinal(content.getBytes(StandardCharsets.UTF_8)),
                    Base64.NO_WRAP
            );
        } catch (InvalidKeyException |
                NoSuchAlgorithmException |
                KeyStoreException |
                UnrecoverableEntryException |
                NoSuchPaddingException |
                BadPaddingException |
                IllegalBlockSizeException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
        return "";
    }

    private String getDecryptContent(byte[] content) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            KeyStore.SecretKeyEntry secretKeyEntry =
                    (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null);
            if (secretKeyEntry == null) {
                Log.d("MoaLib", "SecretKeyEntry is null");
                return "";
            }
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKeyEntry.getSecretKey(),
                    new GCMParameterSpec(128, getIV())
            );
            return new String(cipher.doFinal(content), StandardCharsets.UTF_8);
        } catch (NoSuchPaddingException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                KeyStoreException |
                UnrecoverableEntryException |
                IllegalBlockSizeException |
                BadPaddingException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
        return "";
    }

    private byte[] getIV() {
        SharedPreferences pref =
                context.getSharedPreferences("IV_AuthToken", Context.MODE_PRIVATE);
        return Base64.decode(pref.getString("iv", ""), Base64.NO_WRAP);
    }

    private void setIV(byte[] iv) {
        SharedPreferences pref =
                context.getSharedPreferences("IV_AuthToken", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("iv", Base64.encodeToString(iv, Base64.NO_WRAP));
        editor.apply();
    }
}
