package org.moa.wallet.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.webkit.WebView;

import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.android.crypto.coreapi.PBKDF2;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.wallet.android.api.MoaBridge;
import org.moa.wallet.android.api.MoaCommon;
import org.moa.wallet.android.api.MoaECDSAReceiver;
import org.moa.wallet.android.api.MoaWalletLibReceiver;

import java.io.IOException;
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
import java.util.Map;
import java.util.StringTokenizer;
import java.util.WeakHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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

    private Wallet(Builder builder) {
        if (builder == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Builder is null");
        this.context = builder.context;
        moaWalletReceiver = builder.receiver;
        initKeyStore();
        initProperties();
        pbkdf2 = new PBKDF2(getValuesInPreferences("Hash.Alg"));
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to check key alias");
        }
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(androidProvider);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to init keystore");
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
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to create wallet key pair");
        }
    }

    private void setValuesInPreferences(String key, String value) {
        if (key == null || value == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Key or value is null");
        SharedPreferences pref = context.getSharedPreferences("moaWallet", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        if (key == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Key is null");
        SharedPreferences pref = context.getSharedPreferences("moaWallet", Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            value = "";
        return value;
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void setWebView(WebView webview) {
        if (webview == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Web view is null");
        webview.getSettings().setJavaScriptEnabled(true);
        webview.addJavascriptInterface(new MoaBridge(this), "ECDSA");
        webview.loadUrl("file:///android_asset/ECDSA/ECDSA.html");
        this.webView = webview;
    }

    public void setRestoreInfo(String password, String msg) {
        if (msg == null || msg.length() == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Msg is null");
        StringTokenizer st = new StringTokenizer(msg, "$");
        byte[] encPrk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        byte[] encPuk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        setValuesInPreferences("Salt.Value", MoaBase58.encode(Base64.decode(st.nextToken(), Base64.NO_WRAP)));
        this.password = password;
        byte[] puk = getPBKDF2Data(Cipher.DECRYPT_MODE, password, encPuk);
        String base58Puk = MoaBase58.encode(puk);

        byte[] walletAddress = generateAddress(puk);
        if (walletAddress.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Wallet address not validate");
        String base58Address = MoaBase58.encode(walletAddress);

        byte[] lastEncryptedPrk = getRSAData(Cipher.ENCRYPT_MODE, encPrk);
        if (lastEncryptedPrk.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Prk length not validate");
        String base58CipheredPrk = MoaBase58.encode(lastEncryptedPrk);

        WeakHashMap<String, String> requiredDataForMAC = new WeakHashMap<>();
        requiredDataForMAC.put("cipheredPrk", base58CipheredPrk);
        requiredDataForMAC.put("puk", base58Puk);
        requiredDataForMAC.put("address", base58Address);
        requiredDataForMAC.put("pw", password);
        setWalletPref(requiredDataForMAC);
        this.password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onLibCompleteWallet();
    }

    public byte[] hexStringToByteArray(String s) {
        if (s == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "S is null");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String byteArrayToHexString(byte[] bytes) {
        if (bytes == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Bytes is null");
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public void generateInfo(String password) {
        if (password == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Password is null");
        String curve = getValuesInPreferences("ECC.Curve");
        webView.loadUrl("javascript:doGenerate('" + curve + "')");
        this.password = password;
    }

    public void generateSignedTransaction(String transaction, String password) {
        if (transaction == null || password == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Transaction or password is null");
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

    public String getPublicKey() {
        String base58Puk = getValuesInPreferences("Wallet.PublicKey");
        byte[] decode = MoaBase58.decode(base58Puk);
        return byteArrayToHexString(decode);
    }

    public String getAddress() {
        return getValuesInPreferences("Wallet.Addr");
    }

    public void removeWallet() {
        SharedPreferences sp = context.getSharedPreferences("moaWallet", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.remove("Ciphered.Data");
        editor.remove("Wallet.PublicKey");
        editor.remove("Wallet.Addr");
        editor.remove("MAC.Data");
        editor.apply();
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

    private byte[] generateDerivedKey(String psw) {
        if (psw == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Psw is null");
        int iterationCount = Integer.parseInt(getValuesInPreferences("Iteration.Count"));
        int keySize = 48;
        byte[] salt = getSalt();
        byte[] pw = psw.getBytes();
        return pbkdf2.kdfGen(pw, salt, iterationCount, keySize);
    }

    private byte[] getPBKDF2Data(int encOrDecMode, String psw, byte[] data) {
        if (encOrDecMode != Cipher.ENCRYPT_MODE && encOrDecMode != Cipher.DECRYPT_MODE)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "EncOrDecMode not validate");
        if (psw == null || data == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Psw or data is null");
        byte[] derivedKey = generateDerivedKey(psw);
        if (derivedKey.length != 48)
            return new byte[0];
        String transformationAES = "AES/CTR/NoPadding";
        int keySize = Integer.parseInt(getValuesInPreferences("Symmetric.KeySize")) / 8;
        byte[] key = new byte[keySize];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformationAES, iv, key);
        return symmetricCrypto.getSymmetricData(encOrDecMode, data);
    }

    private byte[] generateAddress(byte[] publicKey) {
        if (publicKey == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Public Key is null");
        String hashAlg = getValuesInPreferences("Hash.Alg");
        byte[] hashPuk = MoaCommon.getInstance().hashDigest(hashAlg, publicKey);
        byte[] ethAddress = new byte[20];
        System.arraycopy(hashPuk, 12, ethAddress, 0, ethAddress.length);
        return ethAddress;
    }

    private String generateMACData(String base58Salt, String psw, String targetMacData) {
        if (base58Salt == null || psw == null || targetMacData == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Base58Salt or psw or targetMacData is null");
        String hmacAlg = getValuesInPreferences("MAC.Alg");
        String hashAlg = getValuesInPreferences("Hash.Alg");
        byte[] saltPassword = getMergedByteArray(MoaBase58.decode(base58Salt), psw.getBytes());
        byte[] hmacKey = MoaCommon.getInstance().hashDigest(hashAlg, saltPassword);
        byte[] macDataBytes = MoaCommon.getInstance().hmacDigest(hmacAlg, targetMacData.getBytes(), hmacKey);
        return MoaBase58.encode(macDataBytes);
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        if (first == null || second == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "First or second is null");
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getRSAData(int encOrDecMode, byte[] data) {
        if (encOrDecMode != Cipher.ENCRYPT_MODE && encOrDecMode != Cipher.DECRYPT_MODE)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "EncOrDecMode not validate");
        if (data == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Data is null");
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
            String transformationRSA = "RSA/ECB/PKCS1Padding";
            Cipher cipher = Cipher.getInstance(transformationRSA);
            if (encOrDecMode == Cipher.ENCRYPT_MODE) {
                PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
                if (publicKey == null)
                    throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Public key is null");
                cipher.init(encOrDecMode, publicKey);
            } else {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                if (privateKey == null)
                    throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Private key is null");
                cipher.init(encOrDecMode, privateKey);
            }
            return cipher.doFinal(data);
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException | UnrecoverableKeyException e) {
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Failed to get RSA data");
        }
    }

    private void setWalletPref(Map<String, String> requiredDataForMAC) {
        if (requiredDataForMAC == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "RequiredDataForMAC is null");
        String base58CipheredPrk = requiredDataForMAC.get("cipheredPrk");
        String base58Puk = requiredDataForMAC.get("puk");
        String base58Address = requiredDataForMAC.get("address");
        setValuesInPreferences("Ciphered.Data", base58CipheredPrk);
        setValuesInPreferences("Wallet.PublicKey", base58Puk);
        setValuesInPreferences("Wallet.Addr", base58Address);

        String osInfo = System.getProperty("os.name");
        setValuesInPreferences("OS.Info", osInfo);

        String versionInfo = String.valueOf(getValuesInPreferences("Version.Info"));
        String iterationCount = String.valueOf(getValuesInPreferences("Iteration.Count"));
        String base58Salt = getValuesInPreferences("Salt.Value");
        String targetMacData = versionInfo + osInfo + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        String macDataBase58 = generateMACData(base58Salt, requiredDataForMAC.get("pw"), targetMacData);
        setValuesInPreferences("MAC.Data", macDataBase58);
    }

    private boolean checkMACData(String psw) {
        if (psw == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Psw is null");
        if (getAddress().length() == 0)
            return false;
        int versionInfo = Integer.parseInt(getValuesInPreferences("Version.Info"));
        String osName = getValuesInPreferences("OS.Info");
        String base58Salt = getValuesInPreferences("Salt.Value");
        int iterationCount = Integer.parseInt(getValuesInPreferences("Iteration.Count"));
        String base58CipheredPrk = getValuesInPreferences("Ciphered.Data");
        String base58Puk = getValuesInPreferences("Wallet.PublicKey");
        String base58Address = getValuesInPreferences("Wallet.Addr");
        String base58MAC = getValuesInPreferences("MAC.Data");
        String mergedWalletData = versionInfo + osName + base58Salt + iterationCount + base58CipheredPrk + base58Puk + base58Address;
        String newMacDataBase58 = generateMACData(base58Salt, psw, mergedWalletData);
        return base58MAC.equals(newMacDataBase58);
    }

    private byte[] getDecryptedPrivateKey(String psw) {
        if (psw == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Psw is null");
        String lastEncryptedPrk = getValuesInPreferences("Ciphered.Data");
        if (lastEncryptedPrk.length() == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Prk not validate");

        int cipherMode = Cipher.DECRYPT_MODE;
        byte[] decode = MoaBase58.decode(lastEncryptedPrk);
        byte[] firstEncryptedPrk = getRSAData(cipherMode, decode);
        return getPBKDF2Data(cipherMode, psw, firstEncryptedPrk);
    }

    private void setInfo(byte[][] walletKeyPair) {
        if (walletKeyPair == null || walletKeyPair.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "WalletKeyPair not validate");
        String base58Puk = MoaBase58.encode(walletKeyPair[1]);

        byte[] walletAddress = generateAddress(walletKeyPair[1]);
        if (walletAddress.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Wallet address not validate");
        String base58Address = MoaBase58.encode(walletAddress);

        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] firstEncryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (firstEncryptedPrk.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "First prk not validate");
        byte[] lastEncryptedPrk = getRSAData(cipherMode, firstEncryptedPrk);
        if (lastEncryptedPrk.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Last prk not validate");
        String base58CipheredPrk = MoaBase58.encode(lastEncryptedPrk);

        WeakHashMap<String, String> requiredDataForMAC = new WeakHashMap<>();
        requiredDataForMAC.put("cipheredPrk", base58CipheredPrk);
        requiredDataForMAC.put("puk", base58Puk);
        requiredDataForMAC.put("address", base58Address);
        requiredDataForMAC.put("pw", password);
        setWalletPref(requiredDataForMAC);
        this.password = "";
        if (moaWalletReceiver != null)
            moaWalletReceiver.onLibCompleteWallet();
    }

    private String generateRestoreDataFormat(byte[][] walletKeyPair) {
        if (walletKeyPair == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "WalletKeyPair is null");
        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] encryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (encryptedPrk.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Prk is null");
        byte[] encryptedPuk = getPBKDF2Data(cipherMode, password, walletKeyPair[1]);
        if (encryptedPuk.length == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Puk is null");
        return Base64.encodeToString(encryptedPrk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(encryptedPuk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(getSalt(), Base64.NO_WRAP);
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        if (prk == null || puk == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Prk or puk is null");
        if (moaWalletReceiver == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Receiver is null");
        byte[][] keyPair = new byte[2][];
        keyPair[0] = hexStringToByteArray(prk);
        keyPair[1] = hexStringToByteArray(puk);
        setInfo(keyPair);
        moaWalletReceiver.onLibCompleteRestoreMsg(generateRestoreDataFormat(keyPair));
    }

    @Override
    public void onSuccessSign(String sign) {
        password = "";
        if (moaWalletReceiver == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Receiver is null");
        moaWalletReceiver.onLibCompleteSign(sign);
    }

    public static class Builder {
        private Context context;
        private MoaWalletLibReceiver receiver;

        public Builder(Context context) {
            this.context = context;
        }

        public Builder addReceiver(MoaWalletLibReceiver receiver) {
            this.receiver = receiver;
            return this;
        }

        public Wallet build() {
            return new Wallet(this);
        }
    }
}