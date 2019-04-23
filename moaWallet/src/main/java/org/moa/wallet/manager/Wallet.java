package org.moa.wallet.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;
import android.webkit.WebView;

import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.android.crypto.coreapi.PBKDF2;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.wallet.android.api.MoaBridge;
import org.moa.wallet.android.api.MoaConfigurable;
import org.moa.wallet.android.api.MoaWalletReceiver;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class Wallet implements MoaConfigurable, MoaWalletReceiver {
    private final String keyAlias = "MoaWalletEncDecKeyPair";
    private final String androidProvider = "AndroidKeyStore";
    private Context context;
    private MoaWalletReceiver moaWalletReceiver;
    private KeyStore keyStore;
    private PBKDF2 pbkdf2;
    private WebView webView;
    private String password = "";

    private Wallet(Builder builder) {
        this.context = builder.context;
        moaWalletReceiver = builder.receiver;
        initKeyStore();
        initProperties();
        pbkdf2 = new PBKDF2(getValuesInPreferences(MoaConfigurable.KEY_WALLET_HASH_ALGORITHM));
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[Wallet] failed to check key alias");
        }
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(androidProvider);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[Wallet][initKeyStore] failed to init keystore");
            throw new RuntimeException("Failed to init keystore", e);
        }
    }

    private void generateKey() {
        Calendar startData = Calendar.getInstance();
        Calendar endData = Calendar.getInstance();
        endData.add(Calendar.YEAR, 25);

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", androidProvider);
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
            Log.d("MoaLib", "[Wallet][generateKey] Failed to create wallet key pair");
            throw new RuntimeException("Failed to create wallet key pair", e);
        }
    }

    @Override
    public void setValuesInPreferences(String key, String value) {
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_WALLET, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_WALLET, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            value = "";
        return value;
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void setWebView(WebView webview) {
        if (webview == null)
            return;
        webview.getSettings().setJavaScriptEnabled(true);
        webview.addJavascriptInterface(new MoaBridge(this), "ECDSA");
        webview.loadUrl("file:///android_asset/ECDSA/ECDSA.html");
        this.webView = webview;
    }

    public boolean existPreferences() {
        String walletAddress = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ADDRESS);
        return walletAddress.length() > 0;
    }

    public void generateInfo(String password) {
        byte[][] walletKeyPair = generateKeyPair();
        if (walletKeyPair.length == 0)
            return;
        this.password = password;
        setInfo(walletKeyPair);
        this.password = "";
    }

    public byte[] generateSignedTransactionData(String transaction, String password) {
        byte[] signData = {0,};
        if (!checkMACData(password))
            return signData;

        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null || privateKeyBytes.length == 0)
            return signData;

        String signatureAlgorithm = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SIGNATURE_ALGIROTHM);
        String keyPairAlgorithm = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_ALGORITHM);
        if (signatureAlgorithm.length() == 0 || keyPairAlgorithm.length() == 0)
            return signData;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            signData = generateSignedData(signatureAlgorithm, privateKey, transaction.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[Wallet][generateSignedTransactionData] failed to get signed transaction data", e);
        }
        return signData;
    }

    public PublicKey getPublicKey() {
        if (!existPreferences())
            return null;

        String base58WalletPuk = getValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY);
        String keyPairAlgorithm = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_ALGORITHM);
        if (base58WalletPuk.length() == 0 || keyPairAlgorithm.length() == 0)
            return null;

        byte[] puk = MoaBase58.decode(base58WalletPuk);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(puk));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[Wallet][getPublicKey] failed to get wallet public key", e);
        }
        return null;
    }

    public boolean verifySignedData(String plainText, byte[] signedData) {
        try {
            String algorithm = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SIGNATURE_ALGIROTHM);
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(getPublicKey());
            signature.update(plainText.getBytes());
            return signature.verify(signedData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[Wallet][verifySignedData] Failed to verify sign data", e);
        }
        return false;
    }

    private void initProperties() {
        if (getValuesInPreferences(MoaConfigurable.KEY_WALLET_VERSION_INFO).length() > 0)
            return;
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_VERSION_INFO, "1");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_SYMMETRIC_ALGORITHM, "AES/CBC/PKCS7Padding");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_SYMMETRIC_KEY_SIZE, "256");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_HASH_ALGORITHM, "SHA256");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_SIGNATURE_ALGIROTHM, "SHA256withECDSA");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_ALGORITHM, "EC");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_CURVE, "secp256r1");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_ALGORITHM, "HmacSHA256");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_ITERATION_COUNT, "4096");
    }

    private byte[] getSalt() {
        String base58Salt = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SALT);
        if (base58Salt == null || base58Salt.length() == 0) {
            byte[] salt = new byte[64];
            new SecureRandom().nextBytes(salt);
            setValuesInPreferences(MoaConfigurable.KEY_WALLET_SALT, MoaBase58.encode(salt));
            return salt;
        } else
            return MoaBase58.decode(base58Salt);
    }

    private byte[][] generateKeyPair() {
        String keyPairAlgorithm = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_ALGORITHM);
        String standardName = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_CURVE);
        byte[][] walletKeyPair = new byte[2][];
        if (keyPairAlgorithm.length() == 0 || standardName.length() == 0)
            return walletKeyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm);
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(standardName);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            walletKeyPair[0] = keyPair.getPrivate().getEncoded();
            walletKeyPair[1] = keyPair.getPublic().getEncoded();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[Wallet][generateKeyPair] Failed to get wallet key pair", e);
        }
        return walletKeyPair;
    }

    private byte[] generateDerivedKey(String psw) {
        int iterationCount = Integer.parseInt(getValuesInPreferences(MoaConfigurable.KEY_WALLET_ITERATION_COUNT));
        int keySize = 48;
        byte[] salt = getSalt();
        byte[] pw = psw.getBytes();
        return pbkdf2.kdfGen(pw, salt, iterationCount, keySize);
    }

    private byte[] getPBKDF2Data(int encOrDecMode, String psw, byte[] data) {
        byte[] resultData = {0,};
        byte[] derivedKey = generateDerivedKey(psw);
        if (derivedKey.length != 48)
            return resultData;

        String transformationAES = "AES/CBC/PKCS7Padding";
        int keySize = Integer.parseInt(getValuesInPreferences(MoaConfigurable.KEY_WALLET_SYMMETRIC_KEY_SIZE)) / 8;
        byte[] key = new byte[keySize];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformationAES, iv, key);
        resultData = symmetricCrypto.getSymmetricData(encOrDecMode, data);
        return resultData;
    }

    private byte[] generateAddress(byte[] publicKey) {
        Log.d("kkk", "public key hex string [" + byteArrayToHexString(publicKey) + "]");
        byte[] walletAddress = {0,};
        String hashAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlg.length() == 0)
            return walletAddress;
        byte[] hashPuk = hashDigest(hashAlg, publicKey);
        Log.d("kkk", "hashed public key [" + byteArrayToHexString(hashPuk) + "]");
        byte[] ethAddress = new byte[20];
        System.arraycopy(hashPuk, 12, ethAddress, 0, ethAddress.length);
        Log.d("kkk", "ethereum base address [" + byteArrayToHexString(ethAddress) + "]");
        return ethAddress;
    }

    private String generateMACData(String base58Salt, String psw, String targetMacData) {
        String macData = "";
        String hmacAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_ALGORITHM);
        String hashAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_HASH_ALGORITHM);
        if (hmacAlg.length() == 0 || hashAlg.length() == 0)
            return macData;
        byte[] saltPassword = getMergedByteArray(MoaBase58.decode(base58Salt), psw.getBytes());
        byte[] hmacKey = hashDigest(hashAlg, saltPassword);
        byte[] macDataBytes = hmacDigest(hmacAlg, targetMacData.getBytes(), hmacKey);
        return MoaBase58.encode(macDataBytes);
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
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
                    Log.d("MoaLib", "[Wallet][getRSAData] public key is null");
                    return resultData;
                }
                cipher.init(encOrDecMode, publicKey);
            } else if (encOrDecMode == Cipher.DECRYPT_MODE) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                if (privateKey == null) {
                    Log.d("MoaLib", "[Wallet][getRSAData] private key is null");
                    return resultData;
                }
                cipher.init(encOrDecMode, privateKey);
            }
            resultData = cipher.doFinal(data);
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException | UnrecoverableKeyException e) {
            Log.d("MoaLib", "[Wallet][getRSAData] failed to get RSA data");
        }
        return resultData;
    }

    private void setWalletPref(List<String> requiredDataForMAC) {
        String base58CipheredPrk = requiredDataForMAC.get(0);
        String base58Puk = requiredDataForMAC.get(1);
        String base58Address = requiredDataForMAC.get(2);
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_CIPHERED_DATA, base58CipheredPrk);
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY, base58Puk);
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_ADDRESS, base58Address);

        String osInfo = System.getProperty("os.name");
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_OS_INFO, osInfo);

        String versionInfo = String.valueOf(getValuesInPreferences(MoaConfigurable.KEY_WALLET_VERSION_INFO));
        String iterationCount = String.valueOf(getValuesInPreferences(MoaConfigurable.KEY_WALLET_ITERATION_COUNT));
        String base58Salt = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SALT);
        String targetMacData = versionInfo + osInfo + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        String macDataBase58 = generateMACData(base58Salt, requiredDataForMAC.get(3), targetMacData);
        setValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_DATA, macDataBase58);
    }

    private boolean checkMACData(String psw) {
        if (!existPreferences())
            return false;
        int versionInfo = Integer.parseInt(getValuesInPreferences(MoaConfigurable.KEY_WALLET_VERSION_INFO));
        String osName = getValuesInPreferences(MoaConfigurable.KEY_WALLET_OS_INFO);
        String base58Salt = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SALT);
        int iterationCount = Integer.parseInt(getValuesInPreferences(MoaConfigurable.KEY_WALLET_ITERATION_COUNT));
        String base58CipheredPrk = getValuesInPreferences(MoaConfigurable.KEY_WALLET_CIPHERED_DATA);
        String base58Puk = getValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY);
        String base58Address = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ADDRESS);
        String base58MAC = getValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_DATA);
        if (osName.length() == 0 || base58Salt.length() == 0 || base58CipheredPrk.length() == 0
                || base58Puk.length() == 0 || base58Address.length() == 0 || base58MAC.length() == 0)
            return false;
        String mergedWalletData = versionInfo + osName + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        byte[] salt = MoaBase58.decode(base58Salt);
        byte[] mergedSaltAndPassword = getMergedByteArray(salt, psw.getBytes());
        String hashAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlg.length() == 0)
            return false;
        byte[] hmacKey = hashDigest(hashAlg, mergedSaltAndPassword);
        String macAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_ALGORITHM);
        if (macAlg.length() == 0)
            return false;
        byte[] macData = hmacDigest(macAlg, mergedWalletData.getBytes(), hmacKey);
        String newMacDataBase58 = MoaBase58.encode(macData);
        return base58MAC.equals(newMacDataBase58);
    }

    private byte[] getDecryptedPrivateKey(String psw) {
        byte[] privateKey = {0,};
        String lastEncryptedPrk = getValuesInPreferences(MoaConfigurable.KEY_WALLET_CIPHERED_DATA);
        if (lastEncryptedPrk.length() == 0)
            return privateKey;

        int cipherMode = Cipher.DECRYPT_MODE;
        byte[] decode = MoaBase58.decode(lastEncryptedPrk);
        byte[] firstEncryptedPrk = getRSAData(cipherMode, decode);
        privateKey = getPBKDF2Data(cipherMode, psw, firstEncryptedPrk);
        return privateKey;
    }

    private byte[] generateSignedData(String algorithm, PrivateKey privateKey, byte[] targetData) {
        byte[] resultData = {0,};
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(targetData);
            resultData = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[Wallet][generateSignedData] Failed to get sign data", e);
        }
        return resultData;
    }

    private byte[] hashDigest(String algorithmName, byte[] targetData) {
        byte[] result = {0,};
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(targetData);
            result = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            Log.d("MoaLib", "[Wallet][hashDigeset] Failed to hash", e);
        }
        return result;
    }

    private byte[] hmacDigest(String algorithmName, byte[] targetData, byte[] key) {
        byte[] result = {0,};
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithmName);
            Mac mac = Mac.getInstance(algorithmName);
            mac.init(secretKeySpec);
            mac.update(targetData);
            result = mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.d("MoaLib", "[Wallet][hmacDigest] Failed to hmac", e);
        }
        return result;
    }

    private void setInfo(byte[][] walletKeyPair) {
        if (walletKeyPair.length == 0)
            return;
        String base58Puk = MoaBase58.encode(walletKeyPair[1]);

        byte[] walletAddress = generateAddress(walletKeyPair[1]);
        if (walletAddress.length == 0)
            return;
        String base58Address = MoaBase58.encode(walletAddress);

        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] firstEncryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (firstEncryptedPrk.length == 0)
            return;
        byte[] lastEncryptedPrk = getRSAData(cipherMode, firstEncryptedPrk);
        if (lastEncryptedPrk.length == 0)
            return;
        String base58CipheredPrk = MoaBase58.encode(lastEncryptedPrk);

        List<String> requiredDataForMAC = new ArrayList<>();
        requiredDataForMAC.add(base58CipheredPrk);
        requiredDataForMAC.add(base58Puk);
        requiredDataForMAC.add(base58Address);
        requiredDataForMAC.add(password);
        setWalletPref(requiredDataForMAC);
    }

    // [Start] JS Library

    public void generateInfoJS(String password) {
        String curve = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_CURVE);
        webView.loadUrl("javascript:doGenerate('" + curve + "')");
        this.password = password;
    }

    public void generateSignedTransactionDataJS(String transaction, String password) {
        if (!checkMACData(password)) {
            onSuccessSign("");
            return;
        }
        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            onSuccessSign("");
            return;
        }
        String curve = getValuesInPreferences(KEY_WALLET_ECC_CURVE);
        String signAlg = getValuesInPreferences(KEY_WALLET_SIGNATURE_ALGIROTHM);
        String prk = byteArrayToHexString(privateKeyBytes);
        webView.loadUrl("javascript:doSign('" + curve + "', '" + signAlg + "', '" + transaction + "', '" + prk + "')");
    }

    public void verifySignedDataJS(String plainText, String signedData) {
        String curve = getValuesInPreferences(MoaConfigurable.KEY_WALLET_ECC_CURVE);
        String signAlg = getValuesInPreferences(MoaConfigurable.KEY_WALLET_SIGNATURE_ALGIROTHM);
        String puk = byteArrayToHexString(MoaBase58.decode(getValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY)));
        webView.loadUrl("javascript:doVerify('" + curve + "', '" + signAlg + "', '" + plainText + "', '" + signedData + "', '" + puk + "')");
    }

    public String getPublicKeyJS() {
        String base58Puk = getValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY);
        byte[] decode = MoaBase58.decode(base58Puk);
        return byteArrayToHexString(decode);
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        byte[][] keyPair = new byte[2][];
        keyPair[0] = hexStringToByteArray(prk);
        keyPair[1] = hexStringToByteArray(puk);
        setInfo(keyPair);
        password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessKeyPair("", "");
    }

    @Override
    public void onSuccessSign(String sign) {
        password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessSign(sign);
    }

    @Override
    public void onSuccessVerify(boolean checkSign) {
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessVerify(checkSign);
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

    // [End] JS Library

    public static class Builder {
        private Context context;
        private MoaWalletReceiver receiver;
        private Wallet instance;

        public Builder(Context context) {
            this.context = context;
        }

        public Builder addReceiver(MoaWalletReceiver receiver) {
            this.receiver = receiver;
            return this;
        }

        public Wallet build() {
            if (instance == null)
                instance = new Wallet(this);
            return instance;
        }
    }
}