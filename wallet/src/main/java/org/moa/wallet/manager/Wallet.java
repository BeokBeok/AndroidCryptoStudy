package org.moa.wallet.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;
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
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringTokenizer;

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
    private WebView webView;
    private String password = "";
    private PBKDF2 pbkdf2 = new PBKDF2("SHA384");
    private boolean isPswInitMode;

    private Wallet() {
        initKeyStore();
    }

    public static Wallet getInstance() {
        return Singleton.instance;
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        if (receiver == null) {
            Log.d("MoaLib", "receiver is null");
            return;
        }
        if (prk == null) {
            Log.d("MoaLib", "prk is null");
            return;
        }
        if (puk == null) {
            Log.d("MoaLib", "puk is null");
            return;
        }
        save(
                MoaCommon.getInstance().hexStringToByteArray(prk),
                MoaCommon.getInstance().hexStringToByteArray(puk)
        );
        /* 복원형 지갑 생성을 위한 필수 데이터 생성 완료 콜백 호출 */
        receiver.onLibWalletCreated(
                generateRestoreDataFormat(
                        MoaCommon.getInstance().hexStringToByteArray(prk),
                        MoaCommon.getInstance().hexStringToByteArray(puk)
                )
        );
        password = "";
    }

    @Override
    public void onSuccessSign(String sign) {
        password = "";
        if (receiver == null) {
            Log.d("MoaLib", "receiver is null");
            return;
        }
        receiver.onLibSignCreated(sign);
    }

    @Override
    public void onSuccessVerify(String result) {
        if (receiver == null) {
            Log.d("MoaLib", "receiver is null");
            return;
        }
        receiver.onLibSignVerified(result.equals("true"));
    }

    public void setContext(Context context) {
        this.context = context;
        initProperties();
        initUsingKeys();
    }

    public void setReceiver(MoaWalletLibReceiver receiver) {
        this.receiver = receiver;
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void setWebView(WebView webview) {
        webview.getSettings().setJavaScriptEnabled(true);
        webview.addJavascriptInterface(new MoaBridge(this), "ECDSA");
        webview.post(() -> webview.loadUrl("file:///android_asset/ECDSA/ECDSA.html"));
        this.webView = webview;
    }

    public void save(String password, String msg) {
        if (receiver == null) {
            Log.d("MoaLib", "receiver is null");
            return;
        }
        if (msg.length() == 0) {
            Log.d("MoaLib", "msg size is 0");
            return;
        }
        /* 메시지 분리 */
        StringTokenizer st = new StringTokenizer(msg, "$");
        byte[] encPrk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        byte[] encPuk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        setValuesInPreferences(
                "Salt.Value",
                MoaBase58.getInstance()
                        .encode(
                                Base64.decode(st.nextToken(), Base64.NO_WRAP)
                        )
        );

        /* 지갑 주소 생성 */
        this.password = password;
        byte[] puk = getPBKDF2Data(Cipher.DECRYPT_MODE, password, encPuk);
        byte[] walletAddress = generateAddress(puk);
        if (walletAddress.length == 0) {
            Log.d("MoaLib", "Wallet address not validate");
            this.password = "";
            return;
        }

        /* 개인키 암호화 (2차) */
        byte[] lastEncryptedPrk = getRSAData(Cipher.ENCRYPT_MODE, encPrk);
        if (lastEncryptedPrk.length == 0) {
            Log.d("MoaLib", "Private Key not validate");
            this.password = "";
            return;
        }

        /* 지갑 데이터 저장 */
        HashMap<String, String> requiredDataForMAC = new HashMap<>();
        requiredDataForMAC.put("cipheredPrk", MoaBase58.getInstance().encode(lastEncryptedPrk));
        requiredDataForMAC.put("puk", MoaBase58.getInstance().encode(puk));
        requiredDataForMAC.put("address", MoaBase58.getInstance().encode(walletAddress));
        setWalletPref(requiredDataForMAC);

        /* 지갑 생성 완료 콜백 호출 */
        this.password = "";
        receiver.onLibRestoreCompleted();
    }

    public void create(String password) {
        /* 키 생성 요청, 키 생성 완료 시 onSuccessKeyPair 콜백 호출됨 */
        String curve = getValuesInPreferences("ECC.Curve");
        webView.post(() -> webView.loadUrl("javascript:doGenerate('" + curve + "')"));
        this.password = password;
    }

    public boolean verifyPsw(String password, String msg) {
        if (msg.length() == 0) {
            Log.d("MoaLib", "msg size is 0");
            return false;
        }
        StringTokenizer st = new StringTokenizer(msg, "%");
        byte[] hmacEncryptedPuk = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        String[] msgSplit = st.nextToken().split("\\$");
        byte[] newHmacEncryptedPuk = MoaCommon.getInstance()
                .hmacDigest(
                        getValuesInPreferences("MAC.Alg"),
                        Base64.decode(msgSplit[1], Base64.NO_WRAP),
                        password.getBytes()
                );
        return Arrays.equals(hmacEncryptedPuk, newHmacEncryptedPuk);
    }

    public byte[] getHmacPsw(String psw) {
        /* hmac 생성 (14 byte);지갑 비밀번호 */
        byte[] hashPsw = MoaCommon.getInstance().
                hashDigest(getValuesInPreferences("Hash.Alg"), psw.getBytes());
        byte[] hmacPsw = MoaCommon.getInstance().
                hmacDigest(getValuesInPreferences("MAC.Alg"), psw.getBytes(), hashPsw);
        if (hashPsw[0] % 2 == 0) {
            return Arrays.copyOfRange(hmacPsw, 14, 14 * 2);
        } else {
            return Arrays.copyOf(hmacPsw, 14);
        }
    }

    public byte[] getEncryptedHmacPsw(String id, String psw, String dateOfBirth) {
        /* hmac 생성 (14 byte);지갑 비밀번호 */
        byte[] hmacPsw = getHmacPsw(psw);

        /* 암호화된 hmac 생성 */
        // 생년월일 기반 PBKDF2 생성
        byte[] dk = pbkdf2.kdfGen(
                dateOfBirth.getBytes(),
                id.getBytes(), // Salt
                10,
                48
        );
        Symmetric symmetric = new Symmetric(
                "AES/CBC/PKCS7Padding",
                Arrays.copyOfRange(dk, 32, dk.length), // iv
                Arrays.copyOf(dk, 32) // dbk
        );
        byte[] random = new byte[1];
        new SecureRandom().nextBytes(random);
        byte[] encryptedHmacPsw = symmetric.getSymmetricData(
                Cipher.ENCRYPT_MODE,
                getMergedByteArray(random, hmacPsw)
        );

        /* 암호화된 hmac 기반 hmac 생성 */
        byte[] hmacEncryptedHmacPsw = MoaCommon.getInstance()
                .hmacDigest(
                        getValuesInPreferences("MAC.Alg"),
                        encryptedHmacPsw,
                        dateOfBirth.getBytes()
                );

        /* 암호화된 hmac 기반 hmac 의 절반 크기의 hmac 생성 */
        byte[] halfHmacEncryptedHmacPsw = new byte[hmacEncryptedHmacPsw.length / 2];
        for (int i = 0; i < halfHmacEncryptedHmacPsw.length; i++) {
            halfHmacEncryptedHmacPsw[i] =
                    (byte) (hmacEncryptedHmacPsw[i] ^
                            hmacEncryptedHmacPsw[i + halfHmacEncryptedHmacPsw.length]);
        }

        /* 암호화된 hmac + 절반 크기의 hmac */
        return getMergedByteArray(encryptedHmacPsw, halfHmacEncryptedHmacPsw);
    }

    public void generateSignedTransaction(String transaction, String password) {
        if (!checkMACData(password)) {
            Log.d("MoaLib", "MAC not validate");
            onSuccessSign("");
            return;
        }
        /* 개인키 복호화 */
        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            Log.d("MoaLib", "Private key not validate");
            onSuccessSign("");
            return;
        }
        /* 서명 생성 요청, 서명 생성 완료 시 OnSuccessSign 콜백 호출됨 */
        webView.post(() ->
                webView.loadUrl("javascript:doSign('"
                        + getValuesInPreferences("ECC.Curve") + "', '"
                        + getValuesInPreferences("Signature.Alg") + "', '"
                        + transaction + "', '"
                        + MoaCommon.getInstance().byteArrayToHexString(privateKeyBytes) + "')"
                )
        );
    }

    public void verifiedSign(String transaction, String sign) {
        /* 서명 검증 요청, 검증 완료 시 OnSuccessVerify 콜백 호출됨 */
        webView.post(() ->
                webView.loadUrl("javascript:doVerify('" +
                        getValuesInPreferences("ECC.Curve") + "', '" +
                        getValuesInPreferences("Signature.Alg") + "', '" +
                        transaction + "', '" +
                        sign + "', '" +
                        getPublicKey() + "')"
                )
        );
    }

    public String getPublicKey() {
        return MoaCommon.getInstance()
                .byteArrayToHexString(
                        MoaBase58.getInstance()
                                .decode(getValuesInPreferences("Wallet.PublicKey"))
                );
    }

    public String getAddress() {
        return getValuesInPreferences("Wallet.Addr");
    }

    public void removeWallet() {
        SharedPreferences sp =
                context.getSharedPreferences(getPrefName(), Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.remove("Ciphered.Data");
        editor.remove("Wallet.PublicKey");
        editor.remove("Wallet.Addr");
        editor.remove("MAC.Data");
        editor.apply();
    }

    public void removeTempWallet() {
        SharedPreferences sp =
                context.getSharedPreferences("tempWallet", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.clear().apply();
    }

    public void throwWalletException(Throwable t) {
        if (receiver == null) {
            return;
        }
        receiver.onLibFail(t);
    }

    public boolean verifyEncryptHmacPsw(String dateOfBirth, String encryptedHmacPsw) {
        byte[] decodedEncryptedHmacPsw = Base64.decode(encryptedHmacPsw, Base64.NO_WRAP);
        byte[] firstEncryptHmacPsw = Arrays.copyOfRange(
                decodedEncryptedHmacPsw,
                0,
                decodedEncryptedHmacPsw.length / 2
        );
        byte[] secondEncryptHmacPsw = Arrays.copyOfRange(
                decodedEncryptedHmacPsw,
                decodedEncryptedHmacPsw.length / 2,
                decodedEncryptedHmacPsw.length
        );
        byte[] newHmac = MoaCommon.getInstance().hmacDigest(
                getValuesInPreferences("MAC.Alg"),
                firstEncryptHmacPsw,
                dateOfBirth.getBytes()
        );
        byte[] newSecondEncryptHmacPsw = new byte[newHmac.length / 2];
        for (int i = 0; i < newHmac.length / 2; i++) {
            newSecondEncryptHmacPsw[i] = (byte) (newHmac[i] ^ newHmac[i + 16]);
        }
        return Arrays.equals(secondEncryptHmacPsw, newSecondEncryptHmacPsw);
    }

    public String generateBackUpRestoreDataFormat(@NonNull HashMap<String, String> walletData) {
        setPswInitMode(true);
        initProperties();
        /* Decryption */
        /* HmacPsw */
        byte[] hmacPsw = getDecryptedHmacPsw(
                Objects.requireNonNull(walletData.get("id")),
                Objects.requireNonNull(walletData.get("dateOfBirth")),
                Objects.requireNonNull(walletData.get("encryptedHmacPsw"))
        );
        StringTokenizer st = new StringTokenizer(walletData.get("restoreMsg"), "$");
        /* Prk */
        byte[] prk = getPBKDF2Data(
                Cipher.DECRYPT_MODE,
                MoaCommon.getInstance().byteArrayToHexString(hmacPsw),
                Base64.decode(st.nextToken(), Base64.NO_WRAP)
        );
        /* Puk and Salt */
        byte[] puk = getPBKDF2Data(
                Cipher.DECRYPT_MODE,
                MoaCommon.getInstance().byteArrayToHexString(hmacPsw),
                Base64.decode(st.nextToken(), Base64.NO_WRAP)
        );
        /* save salt */
        byte[] salt = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        setValuesInPreferences("Salt.Value", MoaBase58.getInstance().encode(salt));

        /* Encrypt */
        /* set password */
        password = walletData.get("hmacPsw");
        /* save wallet */
        save(prk, puk);
        /* generate message */
        String backupDataFormat = generateRestoreDataFormat(prk, puk);
        password = "";
        setPswInitMode(false);
        return backupDataFormat;
    }

    public void updateWallet() {
        setPswInitMode(true);
        /* get temp wallet */
        String cipheredData = getValuesInPreferences("Ciphered.Data");
        String puk = getValuesInPreferences("Wallet.PublicKey");
        String addr = getValuesInPreferences("Wallet.Addr");
        String mac = getValuesInPreferences("MAC.Data");
        String salt = getValuesInPreferences("Salt.Value");
        /* update wallet */
        setPswInitMode(false);
        setValuesInPreferences("Ciphered.Data", cipheredData);
        setValuesInPreferences("Wallet.PublicKey", puk);
        setValuesInPreferences("Wallet.Addr", addr);
        setValuesInPreferences("MAC.Data", mac);
        setValuesInPreferences("Salt.Value", salt);
        /* remove temp wallet */
        removeTempWallet();
    }

    private void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(androidProvider);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException |
                NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private void generateKey() {
        Calendar startData = Calendar.getInstance();
        Calendar endData = Calendar.getInstance();
        endData.add(Calendar.YEAR, 25);
        try {
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance("RSA", androidProvider);
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
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private void setValuesInPreferences(String key, String value) {
        SharedPreferences pref =
                context.getSharedPreferences(getPrefName(), Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        SharedPreferences pref =
                context.getSharedPreferences(getPrefName(), Context.MODE_PRIVATE);
        return pref.getString(key, "");
    }

    private void initUsingKeys() {
        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateKey();
            }
        } catch (KeyStoreException e) {
            Log.d("MoaLib", e.getMessage());
        }
    }

    private void initProperties() {
        if (getValuesInPreferences("Version.Info").length() > 0) {
            return;
        }
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
        /* 저장된 Salt가 없으면 생성, 있으면 저장된 Salt 리턴 */
        String base58Salt = getValuesInPreferences("Salt.Value");
        if (base58Salt == null || base58Salt.length() == 0) {
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            setValuesInPreferences("Salt.Value", MoaBase58.getInstance().encode(salt));
            return salt;
        } else {
            return MoaBase58.getInstance().decode(base58Salt);
        }
    }

    private byte[] generateDerivedKey(String psw) {
        return pbkdf2.kdfGen(
                psw.getBytes(),
                getSalt(),
                Integer.parseInt(getValuesInPreferences("Iteration.Count")),
                48
        );
    }

    private byte[] getPBKDF2Data(int encOrDecMode, String psw, byte[] data) {
        byte[] derivedKey = generateDerivedKey(psw);
        if (derivedKey.length != 48) {
            Log.d("MoaLib", "Derived key not validate");
            return new byte[0];
        }
        int keySize = Integer.parseInt(getValuesInPreferences("Symmetric.KeySize")) / 8;
        return new Symmetric(
                getValuesInPreferences("Symmetric.Alg"),
                Arrays.copyOfRange(derivedKey, keySize, derivedKey.length), // IV
                Arrays.copyOf(derivedKey, keySize) // Key
        ).getSymmetricData(encOrDecMode, data);
    }

    private byte[] generateAddress(byte[] publicKey) {
        String hashAlg = getValuesInPreferences("Hash.Alg");
        byte[] hashPuk = MoaCommon.getInstance().hashDigest(hashAlg, publicKey);
        return Arrays.copyOfRange(
                hashPuk,
                12,
                hashPuk.length
        );
    }

    private String generateMACData(String base58Salt, String psw, String targetMacData) {
        byte[] hmacKey = MoaCommon.getInstance()
                .hashDigest(
                        getValuesInPreferences("Hash.Alg"),
                        getMergedByteArray(MoaBase58.getInstance().decode(base58Salt), psw.getBytes())
                );
        byte[] macDataBytes = MoaCommon.getInstance()
                .hmacDigest(
                        getValuesInPreferences("MAC.Alg"),
                        targetMacData.getBytes(),
                        hmacKey
                );
        return MoaBase58.getInstance().encode(macDataBytes);
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getRSAData(int encOrDecMode, byte[] data) {
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            if (encOrDecMode == Cipher.ENCRYPT_MODE) {
                PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
                if (publicKey == null) {
                    Log.d("MoaLib", "Public key is null");
                    return new byte[0];
                }
                cipher.init(encOrDecMode, publicKey);
            } else {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
                if (privateKey == null) {
                    Log.d("MoaLib", "Private key is null");
                    return new byte[0];
                }
                cipher.init(encOrDecMode, privateKey);
            }
            return cipher.doFinal(data);
        } catch (KeyStoreException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException |
                UnrecoverableKeyException e) {
            Log.d("MoaLib", e.getMessage());
        }
        return new byte[0];
    }

    private void setWalletPref(Map<String, String> requiredDataForMAC) {
        /* 개인키, 공개키, 주소, OS 정보 저장 */
        setValuesInPreferences("Ciphered.Data", requiredDataForMAC.get("cipheredPrk"));
        setValuesInPreferences("Wallet.PublicKey", requiredDataForMAC.get("puk"));
        setValuesInPreferences("Wallet.Addr", requiredDataForMAC.get("address"));
        setValuesInPreferences("OS.Info", System.getProperty("os.name"));

        /* MAC 생성 및 저장 */
        String targetMacData =
                getValuesInPreferences("Version.Info")
                        + System.getProperty("os.name")
                        + getValuesInPreferences("Salt.Value")
                        + getValuesInPreferences("Iteration.Count")
                        + requiredDataForMAC.get("cipheredPrk")
                        + requiredDataForMAC.get("puk")
                        + requiredDataForMAC.get("address");
        String macDataBase58 =
                generateMACData(
                        getValuesInPreferences("Salt.Value"),
                        password,
                        targetMacData
                );
        setValuesInPreferences("MAC.Data", macDataBase58);
    }

    private boolean checkMACData(String psw) {
        if (getAddress().length() == 0) {
            Log.d("MoaLib", "Wallet address not validate");
            return false;
        }
        String mergedWalletData = getValuesInPreferences("Version.Info")
                + getValuesInPreferences("OS.Info")
                + getValuesInPreferences("Salt.Value")
                + getValuesInPreferences("Iteration.Count")
                + getValuesInPreferences("Ciphered.Data")
                + getValuesInPreferences("Wallet.PublicKey")
                + getValuesInPreferences("Wallet.Addr");
        String newMacDataBase58 = generateMACData(
                getValuesInPreferences("Salt.Value"),
                psw,
                mergedWalletData
        );
        return getValuesInPreferences("MAC.Data").equals(newMacDataBase58);
    }

    private byte[] getDecryptedPrivateKey(String psw) {
        String lastEncryptedPrk = getValuesInPreferences("Ciphered.Data");
        if (lastEncryptedPrk.length() == 0) {
            Log.d("MoaLib", "Private key not validate");
            return new byte[0];
        }
        byte[] firstEncryptedPrk =
                getRSAData(
                        Cipher.DECRYPT_MODE,
                        MoaBase58.getInstance().decode(lastEncryptedPrk)
                );
        return getPBKDF2Data(Cipher.DECRYPT_MODE, psw, firstEncryptedPrk);
    }

    private void save(byte[] prk, byte[] puk) {
        byte[] walletAddress = generateAddress(puk);
        if (walletAddress.length == 0) {
            Log.d("MoaLib", "Wallet address not validate");
            return;
        }
        byte[] firstEncryptedPrk = getPBKDF2Data(Cipher.ENCRYPT_MODE, password, prk);
        if (firstEncryptedPrk.length == 0) {
            Log.d("MoaLib", "first encryption prk not validate");
            return;
        }
        byte[] lastEncryptedPrk = getRSAData(Cipher.ENCRYPT_MODE, firstEncryptedPrk);
        if (lastEncryptedPrk.length == 0) {
            Log.d("MoaLib", "last encryption prk not validate");
            return;
        }

        /* 지갑 데이터 저장 */
        HashMap<String, String> requiredDataForMAC = new HashMap<>();
        requiredDataForMAC.put("cipheredPrk", MoaBase58.getInstance().encode(lastEncryptedPrk));
        requiredDataForMAC.put("puk", MoaBase58.getInstance().encode(puk));
        requiredDataForMAC.put("address", MoaBase58.getInstance().encode(walletAddress));
        setWalletPref(requiredDataForMAC);
    }

    private String generateRestoreDataFormat(byte[] prk, byte[] puk) {
        byte[] encryptedPrk = getPBKDF2Data(Cipher.ENCRYPT_MODE, password, prk);
        if (encryptedPrk.length == 0) {
            Log.d("MoaLib", "Prk is null");
            return "";
        }
        byte[] encryptedPuk = getPBKDF2Data(Cipher.ENCRYPT_MODE, password, puk);
        if (encryptedPuk.length == 0) {
            Log.d("MoaLib", "Puk is null");
            return "";
        }
        byte[] hmacEncryptedPuk = MoaCommon.getInstance().hmacDigest(
                getValuesInPreferences("MAC.Alg"),
                encryptedPuk,
                password.getBytes()
        );
        /* E[Hmac_puk] % E[prk] $ E[puk] $ salt */
        return Base64.encodeToString(hmacEncryptedPuk, Base64.NO_WRAP) + "%"
                + Base64.encodeToString(encryptedPrk, Base64.NO_WRAP) + "$"
                + Base64.encodeToString(encryptedPuk, Base64.NO_WRAP) + "$"
                + Base64.encodeToString(getSalt(), Base64.NO_WRAP);
    }

    private byte[] getDecryptedHmacPsw(String id, String dateOfBirth, String encryptedHmacPsw) {
        byte[] dk = pbkdf2.kdfGen(
                dateOfBirth.getBytes(),
                id.getBytes(),
                10,
                48
        );
        Symmetric symmetric = new Symmetric(
                "AES/CBC/PKCS7Padding",
                Arrays.copyOfRange(dk, 32, dk.length), // iv
                Arrays.copyOf(dk, 32) // dbk
        );
        byte[] decodedEncryptedHmacPsw = Base64.decode(encryptedHmacPsw, Base64.NO_WRAP);
        byte[] firstEncryptHmacPsw = Arrays.copyOfRange(
                decodedEncryptedHmacPsw,
                0,
                decodedEncryptedHmacPsw.length / 2
        );
        return Arrays.copyOfRange(
                symmetric.getSymmetricData(Cipher.DECRYPT_MODE, firstEncryptHmacPsw),
                1,
                14
        );
    }

    private String getPrefName() {
        return isPswInitMode ? "tempWallet" : "moaWallet";
    }

    private void setPswInitMode(boolean isPswInitMode) {
        this.isPswInitMode = isPswInitMode;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static Wallet instance = new Wallet();
    }
}