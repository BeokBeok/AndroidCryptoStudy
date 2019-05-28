package org.moa.wallet.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebView;

import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.android.crypto.coreapi.PBKDF2;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.wallet.android.api.MoaBridge;
import org.moa.wallet.android.api.MoaECDSAReceiver;
import org.moa.wallet.android.api.MoaWalletLibReceiver;

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
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class Wallet implements MoaECDSAReceiver {
    private final String keyAlias = "MoaWalletEncDecKeyPair";
    private final String androidProvider = "AndroidKeyStore";
    private Context context;
    private MoaWalletLibReceiver moaWalletReceiver;
    private KeyStore keyStore;
    private PBKDF2 pbkdf2;
    private WebView webView;
    private String password = "";
    private String type = CoinKeyMgrType.KEY_GEN_AND_SAVE_APP.getType();

    private Wallet(Builder builder) {
        this.context = builder.context;
        moaWalletReceiver = builder.receiver;
        if (verifyType(type))
            this.type = builder.type;
        initKeyStore();
        initProperties();
        pbkdf2 = new PBKDF2(getValuesInPreferences("Hash.Alg"));
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[Wallet] failed to check key alias");
        }
    }

    private boolean verifyType(String type) {
        if (type == null || type.length() == 0)
            return false;
        return type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_APP.getType()) ||
                type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_HSM.getType()) ||
                type.equals(CoinKeyMgrType.KEY_GEN_HSM_AND_SAVE_HSM_SE.getType());
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

    private void setValuesInPreferences(String key, String value) {
        String prefName = "moaWallet";
        if (type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_HSM.getType()))
            prefName = "moaRestoreWallet";
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        String prefName = "moaWallet";
        if (type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_HSM.getType()))
            prefName = "moaRestoreWallet";
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
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
        String walletAddress = getValuesInPreferences("Wallet.Addr");
        return walletAddress.length() > 0;
    }

    @Deprecated
    public void generateInfo(String password) {
        byte[][] walletKeyPair = generateKeyPair();
        if (walletKeyPair.length == 0)
            return;
        this.password = password;
        setInfo(walletKeyPair);
        this.password = "";
    }

    @Deprecated
    public byte[] generateSignedTransactionData(String transaction, String password) {
        byte[] signData = {0,};
        if (!checkMACData(password))
            return signData;

        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null || privateKeyBytes.length == 0)
            return signData;

        String signatureAlgorithm = getValuesInPreferences("Signature.Alg");
        String keyPairAlgorithm = getValuesInPreferences("ECC.Alg");
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

    @Deprecated
    public PublicKey getPublicKey() {
        if (!existPreferences())
            return null;

        String base58WalletPuk = getValuesInPreferences("Wallet.PublicKey");
        String keyPairAlgorithm = getValuesInPreferences("ECC.Alg");
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

    @Deprecated
    public boolean verifySignedData(String plainText, byte[] signedData) {
        try {
            String algorithm = getValuesInPreferences("Signature.Alg");
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(getPublicKey());
            signature.update(plainText.getBytes());
            return signature.verify(signedData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[Wallet][verifySignedData] Failed to verify sign data", e);
        }
        return false;
    }

    public void setRestoreInfo(String password, String msg) {
        if (msg == null || msg.length() == 0)
            return;
        StringTokenizer st = new StringTokenizer(msg, "$");
        byte[] encPrk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        byte[] encPuk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        setValuesInPreferences("Salt.Value", MoaBase58.encode(Base64.decode(st.nextToken(), Base64.NO_WRAP)));
        this.password = password;
        byte[] puk = getPBKDF2Data(Cipher.DECRYPT_MODE, password, encPuk);
        String base58Puk = MoaBase58.encode(puk);

        byte[] walletAddress = generateAddress(puk);
        if (walletAddress.length == 0)
            return;
        String base58Address = MoaBase58.encode(walletAddress);

        byte[] lastEncryptedPrk = getRSAData(Cipher.ENCRYPT_MODE, encPrk);
        if (lastEncryptedPrk.length == 0)
            return;
        String base58CipheredPrk = MoaBase58.encode(lastEncryptedPrk);

        List<String> requiredDataForMAC = Arrays.asList(base58CipheredPrk, base58Puk, base58Address, password);
        setWalletPref(requiredDataForMAC);
        this.password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onLibCompleteWallet();
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public void generateInfoJS(String password) {
        String curve = getValuesInPreferences("ECC.Curve");
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
        String curve = getValuesInPreferences("ECC.Curve");
        String signAlg = getValuesInPreferences("Signature.Alg");
        String prk = byteArrayToHexString(privateKeyBytes);
        webView.loadUrl("javascript:doSign('" + curve + "', '" + signAlg + "', '" + transaction + "', '" + prk + "')");
    }

    public void verifySignedDataJS(String plainText, String signedData) {
        String curve = getValuesInPreferences("ECC.Curve");
        String signAlg = getValuesInPreferences("Signature.Alg");
        String puk = byteArrayToHexString(MoaBase58.decode(getValuesInPreferences("Wallet.PublicKey")));
        webView.loadUrl("javascript:doVerify('" + curve + "', '" + signAlg + "', '" + plainText + "', '" + signedData + "', '" + puk + "')");
    }

    public String getPublicKeyJS() {
        String base58Puk = getValuesInPreferences("Wallet.PublicKey");
        byte[] decode = MoaBase58.decode(base58Puk);
        return byteArrayToHexString(decode);
    }

    public String getAddress() {
        return getValuesInPreferences("Wallet.Addr");
    }

    private void initProperties() {
        if (getValuesInPreferences("Version.Info").length() > 0)
            return;
        setValuesInPreferences("Version.Info", "1");
        setValuesInPreferences("Symmetric.Alg", "AES/CTR/NoPadding");
        setValuesInPreferences("Symmetric.KeySize", "256");
        setValuesInPreferences("Hash.Alg", "SHA256");
        setValuesInPreferences("Signature.Alg", "SHA256withECDSA");
        setValuesInPreferences("ECC.Alg", "EC");
        setValuesInPreferences("ECC.Curve", "secp256r1");
        setValuesInPreferences("MAC.Alg", "HmacSHA256");
        setValuesInPreferences("Iteration.Count", "4096");
    }

    private byte[] getSalt() {
        String base58Salt = getValuesInPreferences("Salt.Value");
        if (base58Salt == null || base58Salt.length() == 0) {
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            setValuesInPreferences("Salt.Value", MoaBase58.encode(salt));
            return salt;
        } else
            return MoaBase58.decode(base58Salt);
    }

    @Deprecated
    private byte[][] generateKeyPair() {
        String keyPairAlgorithm = getValuesInPreferences("ECC.Alg");
        String standardName = getValuesInPreferences("ECC.Curve");
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
        int iterationCount = Integer.parseInt(getValuesInPreferences("Iteration.Count"));
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

        String transformationAES = "AES/CTR/NoPadding";
        int keySize = Integer.parseInt(getValuesInPreferences("Symmetric.KeySize")) / 8;
        byte[] key = new byte[keySize];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformationAES, iv, key);
        resultData = symmetricCrypto.getSymmetricData(encOrDecMode, data);
        return resultData;
    }

    private byte[] generateAddress(byte[] publicKey) {
        byte[] walletAddress = {0,};
        String hashAlg = getValuesInPreferences("Hash.Alg");
        if (hashAlg.length() == 0)
            return walletAddress;
        byte[] hashPuk = hashDigest(hashAlg, publicKey);
        byte[] ethAddress = new byte[20];
        System.arraycopy(hashPuk, 12, ethAddress, 0, ethAddress.length);
        return ethAddress;
    }

    private String generateMACData(String base58Salt, String psw, String targetMacData) {
        String macData = "";
        String hmacAlg = getValuesInPreferences("MAC.Alg");
        String hashAlg = getValuesInPreferences("Hash.Alg");
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
        setValuesInPreferences("Ciphered.Data", base58CipheredPrk);
        setValuesInPreferences("Wallet.PublicKey", base58Puk);
        setValuesInPreferences("Wallet.Addr", base58Address);

        String osInfo = System.getProperty("os.name");
        setValuesInPreferences("OS.Info", osInfo);

        String versionInfo = String.valueOf(getValuesInPreferences("Version.Info"));
        String iterationCount = String.valueOf(getValuesInPreferences("Iteration.Count"));
        String base58Salt = getValuesInPreferences("Salt.Value");
        String targetMacData = versionInfo + osInfo + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        String macDataBase58 = generateMACData(base58Salt, requiredDataForMAC.get(3), targetMacData);
        setValuesInPreferences("MAC.Data", macDataBase58);
    }

    private boolean checkMACData(String psw) {
        if (!existPreferences())
            return false;
        int versionInfo = Integer.parseInt(getValuesInPreferences("Version.Info"));
        String osName = getValuesInPreferences("OS.Info");
        String base58Salt = getValuesInPreferences("Salt.Value");
        int iterationCount = Integer.parseInt(getValuesInPreferences("Iteration.Count"));
        String base58CipheredPrk = getValuesInPreferences("Ciphered.Data");
        String base58Puk = getValuesInPreferences("Wallet.PublicKey");
        String base58Address = getValuesInPreferences("Wallet.Addr");
        String base58MAC = getValuesInPreferences("MAC.Data");
        if (osName.length() == 0 || base58Salt.length() == 0 || base58CipheredPrk.length() == 0
                || base58Puk.length() == 0 || base58Address.length() == 0 || base58MAC.length() == 0)
            return false;
        String mergedWalletData = versionInfo + osName + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        String newMacDataBase58 = generateMACData(base58Salt, psw, mergedWalletData);
        return base58MAC.equals(newMacDataBase58);
    }

    private byte[] getDecryptedPrivateKey(String psw) {
        byte[] privateKey = {0,};
        String lastEncryptedPrk = getValuesInPreferences("Ciphered.Data");
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

        List<String> requiredDataForMAC = Arrays.asList(base58CipheredPrk, base58Puk, base58Address, password);
        setWalletPref(requiredDataForMAC);
    }

    private String generateRestoreDataFormat(byte[][] walletKeyPair) {
        String result = "";
        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] encryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (encryptedPrk.length == 0)
            return result;
        byte[] encryptedPuk = getPBKDF2Data(cipherMode, password, walletKeyPair[1]);
        if (encryptedPuk.length == 0)
            return result;
        result = Base64.encodeToString(encryptedPrk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(encryptedPuk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(getSalt(), Base64.NO_WRAP);
        return result;
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        byte[][] keyPair = new byte[2][];
        keyPair[0] = hexStringToByteArray(prk);
        keyPair[1] = hexStringToByteArray(puk);
        if (type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_APP.getType())) {
            setInfo(keyPair);
            password = "";
            if (moaWalletReceiver != null)
                moaWalletReceiver.onLibCompleteWallet();
        } else if (type.equals(CoinKeyMgrType.KEY_GEN_AND_SAVE_HSM.getType())) {
            String restoreMsg = generateRestoreDataFormat(keyPair);
            password = "";
            if (moaWalletReceiver != null)
                moaWalletReceiver.onLibCompleteRestoreMsg(restoreMsg);
        }
    }

    @Override
    public void onSuccessSign(String sign) {
        password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onLibCompleteSign(sign);
    }

    @Override
    public void onSuccessVerify(boolean checkSign) {
        if (moaWalletReceiver != null)
            moaWalletReceiver.onLibCompleteVerify(checkSign);
    }

    private enum CoinKeyMgrType {
        INACTIVE("0x90"),
        KEY_GEN_AND_SAVE_APP("0x91"),
        KEY_GEN_AND_SAVE_HSM("0x92"),
        KEY_GEN_HSM_AND_SAVE_HSM_SE("0x93");

        private String type;

        CoinKeyMgrType(String type) {
            this.type = type;
        }

        public String getType() {
            return this.type;
        }
    }

    public static class Builder {
        private Context context;
        private MoaWalletLibReceiver receiver;
        private String type;

        public Builder(Context context) {
            this.context = context;
        }

        public Builder addReceiver(MoaWalletLibReceiver receiver) {
            this.receiver = receiver;
            return this;
        }

        public Builder addType(String type) {
            this.type = type;
            return this;
        }

        public Wallet build() {
            return new Wallet(this);
        }
    }
}