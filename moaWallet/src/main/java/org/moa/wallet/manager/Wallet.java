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
import org.moa.android.crypto.coreapi.Symmetric;
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
    private MoaWalletLibReceiver receiver;
    private KeyStore keyStore;
    private PBKDF2 pbkdf2;
    private WebView webView;
    private String password = "";

    private Wallet() {
        initKeyStore();
    }

    public static Wallet getInstance() {
        return Singleton.instance;
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(androidProvider);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
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
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
        }
    }

    private void setValuesInPreferences(String key, String value) {
        if (key == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "key is null");
            return;
        }
        if (value == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "value is null");
            return;
        }
        SharedPreferences pref = context.getSharedPreferences("moaWallet", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        if (key == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "key is null");
            return "";
        }
        SharedPreferences pref = context.getSharedPreferences("moaWallet", Context.MODE_PRIVATE);
        return pref.getString(key, "");
    }

    public void setContext(Context context) {
        this.context = context;
        initProperties();
        initUsingKeys();
    }

    public void setReceiver(MoaWalletLibReceiver receiver) {
        if (receiver == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "receiver is null");
            return;
        }
        this.receiver = receiver;
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void setWebView(WebView webview) {
        if (webview == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "webView is null");
            return;
        }
        webview.getSettings().setJavaScriptEnabled(true);
        webview.addJavascriptInterface(new MoaBridge(this), "ECDSA");
        webview.loadUrl("file:///android_asset/ECDSA/ECDSA.html");
        this.webView = webview;
    }

    public void setRestoreInfo(String password, String msg) {
        if (msg == null || msg.length() == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "msg is null");
            return;
        }
        StringTokenizer st = new StringTokenizer(msg, "$");
        byte[] encPrk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        byte[] encPuk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        setValuesInPreferences("Salt.Value", MoaBase58.getInstance().encode(Base64.decode(st.nextToken(), Base64.NO_WRAP)));
        this.password = password;
        byte[] puk = getPBKDF2Data(Cipher.DECRYPT_MODE, password, encPuk);
        String base58Puk = MoaBase58.getInstance().encode(puk);

        byte[] walletAddress = generateAddress(puk);
        if (walletAddress.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Wallet address not validate");
            this.password = "";
            return;
        }
        String base58Address = MoaBase58.getInstance().encode(walletAddress);

        byte[] lastEncryptedPrk = getRSAData(Cipher.ENCRYPT_MODE, encPrk);
        if (lastEncryptedPrk.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Private Key not validate");
            this.password = "";
            return;
        }
        String base58CipheredPrk = MoaBase58.getInstance().encode(lastEncryptedPrk);

        WeakHashMap<String, String> requiredDataForMAC = new WeakHashMap<>();
        requiredDataForMAC.put("cipheredPrk", base58CipheredPrk);
        requiredDataForMAC.put("puk", base58Puk);
        requiredDataForMAC.put("address", base58Address);
        requiredDataForMAC.put("pw", password);
        setWalletPref(requiredDataForMAC);
        this.password = "";
        if (receiver == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "receiver is null");
            return;
        }
        receiver.onLibCompleteWallet();
    }

    public byte[] hexStringToByteArray(String s) {
        if (s == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "s is null");
            return new byte[0];
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "bytes is null");
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public void generateInfo(String password) {
        if (password == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "password is null");
            return;
        }
        String curve = getValuesInPreferences("ECC.Curve");
        webView.loadUrl("javascript:doGenerate('" + curve + "')");
        this.password = password;
    }

    public void generateSignedTransaction(String transaction, String password) {
        if (transaction == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "transaction is null");
            return;
        }
        if (password == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "password is null");
            return;
        }
        if (!checkMACData(password)) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "MAC not validate");
            onSuccessSign("");
            return;
        }
        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Private key not validate");
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
        byte[] decode = MoaBase58.getInstance().decode(base58Puk);
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

    private void initUsingKeys() {
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
        }
        pbkdf2 = new PBKDF2(getValuesInPreferences("Hash.Alg"));
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
            setValuesInPreferences("Salt.Value", MoaBase58.getInstance().encode(salt));
            return salt;
        } else
            return MoaBase58.getInstance().decode(base58Salt);
    }

    private byte[] generateDerivedKey(String psw) {
        if (psw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "psw is null");
            return new byte[0];
        }
        int iterationCount = Integer.parseInt(getValuesInPreferences("Iteration.Count"));
        int keySize = 48;
        byte[] salt = getSalt();
        byte[] pw = psw.getBytes();
        return pbkdf2.kdfGen(pw, salt, iterationCount, keySize);
    }

    private byte[] getPBKDF2Data(int encOrDecMode, String psw, byte[] data) {
        if (encOrDecMode != Cipher.ENCRYPT_MODE && encOrDecMode != Cipher.DECRYPT_MODE) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "encOrDecMode is " + encOrDecMode);
            return new byte[0];
        }
        if (psw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "psw is null");
            return new byte[0];
        }
        if (data == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "data is null");
            return new byte[0];
        }
        byte[] derivedKey = generateDerivedKey(psw);
        if (derivedKey.length != 48) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Derived key not validate");
            return new byte[0];
        }
        String transformationAES = "AES/CTR/NoPadding";
        int keySize = Integer.parseInt(getValuesInPreferences("Symmetric.KeySize")) / 8;
        byte[] key = new byte[keySize];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        Symmetric symmetric = new Symmetric(transformationAES, iv, key);
        return symmetric.getSymmetricData(encOrDecMode, data);
    }

    private byte[] generateAddress(byte[] publicKey) {
        if (publicKey == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "public key is null");
            return new byte[0];
        }
        String hashAlg = getValuesInPreferences("Hash.Alg");
        byte[] hashPuk = MoaCommon.getInstance().hashDigest(hashAlg, publicKey);
        byte[] ethAddress = new byte[20];
        System.arraycopy(hashPuk, 12, ethAddress, 0, ethAddress.length);
        return ethAddress;
    }

    private String generateMACData(String base58Salt, String psw, String targetMacData) {
        if (base58Salt == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "base58Salt is null");
            return "";
        }
        if (psw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "psw is null");
            return "";
        }
        if (targetMacData == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "targetMacData is null");
            return "";
        }
        String hmacAlg = getValuesInPreferences("MAC.Alg");
        String hashAlg = getValuesInPreferences("Hash.Alg");
        byte[] saltPassword = getMergedByteArray(MoaBase58.getInstance().decode(base58Salt), psw.getBytes());
        byte[] hmacKey = MoaCommon.getInstance().hashDigest(hashAlg, saltPassword);
        byte[] macDataBytes = MoaCommon.getInstance().hmacDigest(hmacAlg, targetMacData.getBytes(), hmacKey);
        return MoaBase58.getInstance().encode(macDataBytes);
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        if (first == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "first is null");
            return new byte[0];
        }
        if (second == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "second is null");
            return new byte[0];
        }
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getRSAData(int encOrDecMode, byte[] data) {
        if (encOrDecMode != Cipher.ENCRYPT_MODE && encOrDecMode != Cipher.DECRYPT_MODE) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "encOrDecMode is " + encOrDecMode);
            return new byte[0];
        }
        if (data == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "data is null");
            return new byte[0];
        }
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
            String transformationRSA = "RSA/ECB/PKCS1Padding";
            Cipher cipher = Cipher.getInstance(transformationRSA);
            if (encOrDecMode == Cipher.ENCRYPT_MODE) {
                PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
                if (publicKey == null) {
                    Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Public key is null");
                    return new byte[0];
                }
                cipher.init(encOrDecMode, publicKey);
            } else {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                if (privateKey == null) {
                    Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Private key is null");
                    return new byte[0];
                }
                cipher.init(encOrDecMode, privateKey);
            }
            return cipher.doFinal(data);
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException | UnrecoverableKeyException e) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + e.getMessage());
        }
        return new byte[0];
    }

    private void setWalletPref(Map<String, String> requiredDataForMAC) {
        if (requiredDataForMAC == null || requiredDataForMAC.size() != 4) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "requiredDataForMAC not validate");
            return;
        }
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
        if (psw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "psw is null");
            return false;
        }
        if (getAddress().length() == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Wallet address not validate");
            return false;
        }
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
        if (psw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "psw is null");
            return new byte[0];
        }
        String lastEncryptedPrk = getValuesInPreferences("Ciphered.Data");
        if (lastEncryptedPrk.length() == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Private key not validate");
            return new byte[0];
        }
        int cipherMode = Cipher.DECRYPT_MODE;
        byte[] decode = MoaBase58.getInstance().decode(lastEncryptedPrk);
        byte[] firstEncryptedPrk = getRSAData(cipherMode, decode);
        return getPBKDF2Data(cipherMode, psw, firstEncryptedPrk);
    }

    private void setInfo(byte[][] walletKeyPair) {
        if (walletKeyPair == null || walletKeyPair.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "walletKeyPair not validate");
            return;
        }
        String base58Puk = MoaBase58.getInstance().encode(walletKeyPair[1]);

        byte[] walletAddress = generateAddress(walletKeyPair[1]);
        if (walletAddress.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Wallet address not validate");
            return;
        }
        String base58Address = MoaBase58.getInstance().encode(walletAddress);

        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] firstEncryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (firstEncryptedPrk.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "first encryption prk not validate");
            return;
        }
        byte[] lastEncryptedPrk = getRSAData(cipherMode, firstEncryptedPrk);
        if (lastEncryptedPrk.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "last encryption prk not validate");
            return;
        }
        String base58CipheredPrk = MoaBase58.getInstance().encode(lastEncryptedPrk);

        WeakHashMap<String, String> requiredDataForMAC = new WeakHashMap<>();
        requiredDataForMAC.put("cipheredPrk", base58CipheredPrk);
        requiredDataForMAC.put("puk", base58Puk);
        requiredDataForMAC.put("address", base58Address);
        requiredDataForMAC.put("pw", password);
        setWalletPref(requiredDataForMAC);
        this.password = "";
        if (receiver == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "receiver is null");
            return;
        }
        receiver.onLibCompleteWallet();
    }

    private String generateRestoreDataFormat(byte[][] walletKeyPair) {
        if (walletKeyPair == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "walletKeyPair is null");
            return "";
        }
        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] encryptedPrk = getPBKDF2Data(cipherMode, password, walletKeyPair[0]);
        if (encryptedPrk.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Prk is null");
            return "";
        }
        byte[] encryptedPuk = getPBKDF2Data(cipherMode, password, walletKeyPair[1]);
        if (encryptedPuk.length == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Puk is null");
            return "";
        }
        return Base64.encodeToString(encryptedPrk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(encryptedPuk, Base64.NO_WRAP) + "$" +
                Base64.encodeToString(getSalt(), Base64.NO_WRAP);
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        if (prk == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "prk is null");
            return;
        }
        if (puk == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "puk is null");
            return;
        }
        if (receiver == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "receiver is null");
            return;
        }
        byte[][] keyPair = new byte[2][];
        keyPair[0] = hexStringToByteArray(prk);
        keyPair[1] = hexStringToByteArray(puk);
        setInfo(keyPair);
        receiver.onLibCompleteRestoreMsg(generateRestoreDataFormat(keyPair));
    }

    @Override
    public void onSuccessSign(String sign) {
        password = "";
        if (receiver == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "receiver is null");
            return;
        }
        receiver.onLibCompleteSign(sign);
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static Wallet instance = new Wallet();
    }
}