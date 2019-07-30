package org.moa.auth.userauth.manager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

public class FingerprintAuth {
    private final String keyAlias = "MoaFingerKeyPair";
    private String curve;
    private String signAlgorithmSuite;
    private KeyStore keyStore;

    private FingerprintAuth() {
        initKeyStore();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public static FingerprintAuth getInstance() {
        return Singleton.instance;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void init(
            String ecdsaCurve,
            String ecdsaSignAlgorithmSuite
    ) {
        if (ecdsaCurve == null || ecdsaSignAlgorithmSuite == null) {
            Log.d("MoaLib",
                    "ecdsaCurve is " + ecdsaCurve
                            + " or ecdsaSignAlgorithmSuite is " + ecdsaSignAlgorithmSuite
            );
            return;
        }
        this.curve = ecdsaCurve;
        this.signAlgorithmSuite = ecdsaSignAlgorithmSuite;
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
        } catch (KeyStoreException e) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getRegisterSignature(String base64AuthToken) {
        if (base64AuthToken == null) {
            Log.d("MoaLib", "base64AuthToken is null");
            return new byte[0];
        }
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);

            byte[] combineAuthTokenWithPublicKey = getMergedByteArray(
                    Base64.decode(base64AuthToken, Base64.NO_WRAP),
                    publicKey.getEncoded()
            );
            return getSignedData(privateKey, combineAuthTokenWithPublicKey);
        } catch (NoSuchAlgorithmException |
                KeyStoreException |
                UnrecoverableKeyException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getLoginSignature(
            String base64NonceOTP,
            String base64AuthToken
    ) {
        if (base64NonceOTP == null) {
            Log.d("MoaLib", "base64NonceOTP is null");
            return new byte[0];
        }
        if (base64AuthToken == null) {
            Log.d("MoaLib", "base64AuthToken is null");
            return new byte[0];
        }
        byte[] combineNonceOTPWithAuthToken = getMergedByteArray(
                Base64.decode(base64NonceOTP, Base64.NO_WRAP),
                Base64.decode(base64AuthToken, Base64.NO_WRAP)
        );
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            return getSignedData(privateKey, combineNonceOTPWithAuthToken);
        } catch (KeyStoreException |
                NoSuchAlgorithmException |
                UnrecoverableKeyException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    public PublicKey getPublicKey() {
        try {
            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (certificate == null) {
                Log.d("MoaLib", "Certificate is null");
                return null;
            }
            return certificate.getPublicKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return null;
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

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec(curve))
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(10)
                            .build()
            );
            keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException |
                InvalidAlgorithmParameterException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private byte[] getMergedByteArray(
            byte[] first,
            byte[] second
    ) {
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getSignedData(
            PrivateKey privateKey,
            byte[] targetData
    ) {
        try {
            Signature signature = Signature.getInstance(signAlgorithmSuite);
            signature.initSign(privateKey);
            signature.update(targetData);
            return signature.sign();
        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                SignatureException e
        ) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static class Singleton {
        private static final FingerprintAuth instance = new FingerprintAuth();
    }
}
