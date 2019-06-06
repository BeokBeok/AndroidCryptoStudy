package org.moa.auth.userauth.manager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.android.api.MoaTEEUsable;

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

public class FingerprintAuth implements MoaTEEUsable {
    private final String keyAlias = MoaTEEUsable.ALIAS_FINGERPRINT;
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
    public void init(String ecdsaCurve, String ecdsaSignAlgorithmSuite) {
        this.curve = ecdsaCurve;
        this.signAlgorithmSuite = ecdsaSignAlgorithmSuite;
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[FingerprintAuthManager] failed to check key alias");
        }
    }

    @Override
    public void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(MoaTEEUsable.PROVIDER);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][initKeyStore] failed to init keystore");
            Log.d("MoaLib", "Failed to init keystore", e);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void generateKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, MoaTEEUsable.PROVIDER);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec(curve))
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(10)
                            .build()
            );
            keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][generateKey] Failed to create fingerprint key pair");
            Log.d("MoaLib", "Failed to create fingerprint key pair", e);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getRegisterSignature(String base64AuthToken) {
        byte[] resultData;
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();

            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);

            byte[] authToken = Base64.decode(base64AuthToken, Base64.NO_WRAP);
            byte[] combineAuthTokenWithPublicKey = getMergedByteArray(authToken, publicKey.getEncoded());
            resultData = getSignedData(privateKey, combineAuthTokenWithPublicKey);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][getRegisterSignature] Failed to get register signature data");
            Log.d("MoaLib", "Failed to get register signature data", e);
        }
        return resultData;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getLoginSignature(String base64NonceOTP, String base64AuthToken) {
        byte[] resultData;
        byte[] nonceOTP = Base64.decode(base64NonceOTP, Base64.NO_WRAP);
        byte[] authToken = Base64.decode(base64AuthToken, Base64.NO_WRAP);
        byte[] combineNonceOTPWithAuthToken = getMergedByteArray(nonceOTP, authToken);
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            resultData = getSignedData(privateKey, combineNonceOTPWithAuthToken);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][getLoginSignature] Failed to get login signature data");
            Log.d("MoaLib", "Failed to get login signature data", e);
        }
        return resultData;
    }

    public PublicKey getPublicKey() {
        PublicKey publicKey;
        try {
            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (certificate == null) {
                Log.d("MoaLib", "[FingerprintAuthManager][getPublicKey] certificate not validate");
                return null;
            }
            publicKey = certificate.getPublicKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][getPublicKey] failed to get public key");
            Log.d("MoaLib", "Failed to get public key", e);
        }
        return publicKey;
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getSignedData(PrivateKey privateKey, byte[] targetData) {
        byte[] resultData;
        try {
            Signature signature = Signature.getInstance(signAlgorithmSuite);
            signature.initSign(privateKey);
            signature.update(targetData);
            resultData = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[FingerprintAuthManager][getSignedData] Failed to get sign data");
            Log.d("MoaLib", "Failed to get sign data", e);
        }
        return resultData;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static class Singleton {
        private static final FingerprintAuth instance = new FingerprintAuth();
    }
}
