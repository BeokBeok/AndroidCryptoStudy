package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.PBKDF2;
import org.moa.android.crypto.coreapi.RIPEMD160;
import org.moa.android.crypto.coreapi.SymmetricCrypto;
import org.moa.auth.userauth.android.api.MoaCommonFunc;
import org.moa.auth.userauth.android.api.MoaPreferences;
import org.moa.auth.userauth.android.api.MoaTEEKeyStore;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

public class Wallet implements MoaTEEKeyStore, MoaPreferences, MoaCommonFunc {
    private final String keyAlias = MoaTEEKeyStore.ALIAS_WALLET;
    private Context context;
    private KeyStore keyStore;

    private Wallet() {
        initKeyStore();
    }

    public static Wallet getInstance() {
        return Singleton.instance;
    }

    public void init(Context context) {
        this.context = context;
        initProperties();
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[Wallet] failed to check key alias");
        }
    }

    @Override
    public void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(MoaTEEKeyStore.PROVIDER);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[Wallet][initKeyStore] failed to init keystore");
            throw new RuntimeException("Failed to init keystore", e);
        }
    }

    @Override
    public void generateKey() {
        Calendar startData = Calendar.getInstance();
        Calendar endData = Calendar.getInstance();
        endData.add(Calendar.YEAR, 25);

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", MoaTEEKeyStore.PROVIDER);
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
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_WALLET, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaPreferences.PREFNAME_WALLET, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            value = "";
        return value;
    }

    public boolean existPreferences() {
        String walletAddress = getValuesInPreferences(MoaPreferences.KEY_WALLET_ADDRESS);
        return walletAddress.length() > 0;
    }

    public void generateInfo(String psw) {
        byte[][] walletKeyPair = generateKeyPair();
        if (walletKeyPair.length == 0)
            return;
        String base64Puk = Base64.encodeToString(walletKeyPair[1], Base64.NO_WRAP);

        byte[] walletAddressCreatedPuk = generateAddressCreatedWithPublicKey(walletKeyPair[1]);
        if (walletAddressCreatedPuk.length == 0)
            return;
        String base64Address = Base64.encodeToString(walletAddressCreatedPuk, Base64.NO_WRAP);

        int cipherMode = Cipher.ENCRYPT_MODE;
        byte[] firstEncryptedPrk = getPBKDF2Data(cipherMode, psw, walletKeyPair[0]);
        if (firstEncryptedPrk.length == 0)
            return;
        byte[] lastEncryptedPrk = getRSAData(cipherMode, firstEncryptedPrk);
        if (lastEncryptedPrk.length == 0)
            return;
        String base64CipheredPrk = Base64.encodeToString(lastEncryptedPrk, Base64.NO_WRAP);

        List<String> requiredDataForMAC = new ArrayList<>();
        requiredDataForMAC.add(base64CipheredPrk);
        requiredDataForMAC.add(base64Puk);
        requiredDataForMAC.add(base64Address);
        requiredDataForMAC.add(psw);
        setWalletPref(requiredDataForMAC);
    }

    public byte[] generateSignedTransactionData(String transaction, String password) {
        byte[] signData = {0,};
        if (!checkMACData(password))
            return signData;

        byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null)
            return signData;
        if (privateKeyBytes.length == 0)
            return signData;

        String signatureAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_SIGNATURE_ALGIROTHM);
        String keyPairAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_ALGORITHM);
        if (signatureAlgorithm.length() == 0 || keyPairAlgorithm.length() == 0)
            return signData;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            signData = generateSignedData(signatureAlgorithm, privateKey, transaction.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[Wallet][generateSignedTransactionData] failed to get signed transaction data");
            throw new RuntimeException("Failed to get signed transaction data", e);
        }
        return signData;
    }

    public PublicKey getPublicKey() {
        if (!existPreferences())
            return null;

        String base64WalletPuk = getValuesInPreferences(MoaPreferences.KEY_WALLET_PUBLIC_KEY);
        String keyPairAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_ALGORITHM);
        if (base64WalletPuk.length() == 0 || keyPairAlgorithm.length() == 0)
            return null;

        byte[] puk = Base64.decode(base64WalletPuk, Base64.NO_WRAP);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(puk));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[Wallet][getPublicKey] failed to get wallet public key");
        }
        return null;
    }

    public boolean verifySignedData(String plainText, byte[] signedData) {
        try {
            String algorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_SIGNATURE_ALGIROTHM);
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(getPublicKey());
            signature.update(plainText.getBytes());
            return signature.verify(signedData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[Wallet][verifySignedData] Failed to verify sign data");
            throw new RuntimeException("Failed to verify sign data", e);
        }
    }

    private void initProperties() {
        if (getValuesInPreferences(MoaPreferences.KEY_WALLET_VERSION_INFO).length() > 0)
            return;
        setValuesInPreferences(MoaPreferences.KEY_WALLET_VERSION_INFO, "1");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_SYMMETRIC_ALGORITHM, "AES/CBC/PKCS7Padding");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_SYMMETRIC_KEY_SIZE, "256");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM, "SHA384");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_SIGNATURE_ALGIROTHM, "SHA256withECDSA");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_ALGORITHM, "EC");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_CURVE, "secp256r1");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_ALGORITHM, "HmacSHA256");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_ITERATION_COUNT, "8192");
    }

    private byte[] getSalt() {
        String base64Salt = getValuesInPreferences(MoaPreferences.KEY_WALLET_SALT);
        if (base64Salt == null || base64Salt.length() == 0) {
            byte[] salt = new byte[64];
            new SecureRandom().nextBytes(salt);
            setValuesInPreferences(MoaPreferences.KEY_WALLET_SALT, Base64.encodeToString(salt, Base64.NO_WRAP));
            return salt;
        } else
            return Base64.decode(base64Salt, Base64.NO_WRAP);
    }

    private byte[][] generateKeyPair() {
        String keyPairAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_ALGORITHM);
        String standardName = getValuesInPreferences(MoaPreferences.KEY_WALLET_ECC_CURVE);
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
            Log.d("MoaLib", "[Wallet][generateKeyPair] Failed to get wallet key pair");
        }
        return walletKeyPair;
    }

    private byte[] generateDerivedKey(String psw) {
        String hashAlg = getValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM);
        int iterationCount = Integer.parseInt(getValuesInPreferences(MoaPreferences.KEY_WALLET_ITERATION_COUNT));
        int keySize = 48;
        byte[] salt = getSalt();
        byte[] pw = psw.getBytes();
        return PBKDF2.kdfGen(hashAlg, pw, salt, iterationCount, keySize);
    }

    private byte[] getPBKDF2Data(int encOrDecMode, String psw, byte[] data) {
        byte[] resultData = {0,};
        byte[] derivedKey = generateDerivedKey(psw);
        if (derivedKey.length != 48)
            return resultData;

        String transformationAES = "AES/CBC/PKCS7Padding";
        int keySize = Integer.parseInt(getValuesInPreferences(MoaPreferences.KEY_WALLET_SYMMETRIC_KEY_SIZE)) / 8;
        byte[] key = new byte[keySize];
        System.arraycopy(derivedKey, 0, key, 0, key.length);
        byte[] iv = new byte[16];
        System.arraycopy(derivedKey, key.length, iv, 0, iv.length);
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto(transformationAES, iv, key);
        resultData = symmetricCrypto.getSymmetricData(encOrDecMode, data);
        return resultData;
    }

    private byte[] generateAddressCreatedWithPublicKey(byte[] publicKey) {
        byte[] walletAddress = {0,};
        String hashAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlgorithm == null)
            return walletAddress;

        int prefixSize = 1;
        byte[] hashPuk = hashDigest(hashAlgorithm, publicKey);
        byte[] ripemd160 = RIPEMD160.getHash(hashPuk);
        byte[] checksum = new byte[4];
        System.arraycopy(hashPuk, 0, checksum, 0, checksum.length);

        int ethBlockChainAddrLen = prefixSize + ripemd160.length + checksum.length;
        ByteBuffer byteBuffer = ByteBuffer.allocate(ethBlockChainAddrLen);
        byteBuffer.clear();
        byteBuffer.order(ByteOrder.BIG_ENDIAN);

        byteBuffer.put((byte) 0x00);
        byteBuffer.put(ripemd160);
        byteBuffer.put(checksum);
        walletAddress = byteBuffer.array();
        return walletAddress;
    }

    @Deprecated
    private byte[] generateAddressCreatedWithPrivateKey(byte[] privateKey) {
        byte[] walletAddress = {0,};
        String hashAlgorithm = getValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlgorithm == null)
            return walletAddress;

        int prefixSize = 1;
        byte[] hashPrk = hashDigest(hashAlgorithm, privateKey);
        byte[] dualHashPrk = hashDigest(hashAlgorithm, hashPrk);
        byte[] checksum = new byte[4];
        System.arraycopy(dualHashPrk, 0, checksum, 0, checksum.length);

        int ethBlockChainAddrLen = prefixSize + privateKey.length + prefixSize + checksum.length;
        ByteBuffer byteBuffer = ByteBuffer.allocate(ethBlockChainAddrLen);
        byteBuffer.clear();
        byteBuffer.order(ByteOrder.BIG_ENDIAN);

        byteBuffer.put((byte) 0x80);
        byteBuffer.put(privateKey);
        byteBuffer.put((byte) 0x01);
        byteBuffer.put(checksum);
        walletAddress = byteBuffer.array();
        return walletAddress;
    }

    private String generateMACData(String base64Salt, String psw, String targetMacData) {
        String macData = "";
        String hmacAlg = getValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_ALGORITHM);
        String hashAlg = getValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM);
        if (hmacAlg.length() == 0 || hashAlg.length() == 0)
            return macData;
        byte[] saltPassword = getMergedByteArray(Base64.decode(base64Salt, Base64.NO_WRAP), psw.getBytes());
        byte[] hmacKey = hashDigest(hashAlg, saltPassword);
        byte[] macDataBytes = hmacDigest(hmacAlg, targetMacData.getBytes(), hmacKey);
        return Base64.encodeToString(macDataBytes, Base64.NO_WRAP);
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
        String base64CipheredPrk = requiredDataForMAC.get(0);
        String base64Puk = requiredDataForMAC.get(1);
        String base64Address = requiredDataForMAC.get(2);
        setValuesInPreferences(MoaPreferences.KEY_WALLET_CIPHERED_DATA, base64CipheredPrk);
        setValuesInPreferences(MoaPreferences.KEY_WALLET_PUBLIC_KEY, base64Puk);
        setValuesInPreferences(MoaPreferences.KEY_WALLET_ADDRESS, base64Address);

        String osInfo = System.getProperty("os.name");
        setValuesInPreferences(MoaPreferences.KEY_WALLET_OS_INFO, osInfo);

        String versionInfo = String.valueOf(getValuesInPreferences(MoaPreferences.KEY_WALLET_VERSION_INFO));
        String iterationCount = String.valueOf(getValuesInPreferences(MoaPreferences.KEY_WALLET_ITERATION_COUNT));
        String base64Salt = getValuesInPreferences(MoaPreferences.KEY_WALLET_SALT);
        String targetMacData = versionInfo + osInfo + base64Salt + iterationCount + base64CipheredPrk + base64Puk + base64Address;
        String macDataBase58 = generateMACData(base64Salt, requiredDataForMAC.get(3), targetMacData);
        setValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_DATA, macDataBase58);
    }

    private boolean checkMACData(String psw) {
        if (!existPreferences())
            return false;

        int versionInfo = Integer.parseInt(getValuesInPreferences(MoaPreferences.KEY_WALLET_VERSION_INFO));
        String osName = getValuesInPreferences(MoaPreferences.KEY_WALLET_OS_INFO);
        String base64Salt = getValuesInPreferences(MoaPreferences.KEY_WALLET_SALT);
        int iterationCount = Integer.parseInt(getValuesInPreferences(MoaPreferences.KEY_WALLET_ITERATION_COUNT));
        String base64CipheredPrk = getValuesInPreferences(MoaPreferences.KEY_WALLET_CIPHERED_DATA);
        String base64Puk = getValuesInPreferences(MoaPreferences.KEY_WALLET_PUBLIC_KEY);
        String base64Address = getValuesInPreferences(MoaPreferences.KEY_WALLET_ADDRESS);
        String base64MAC = getValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_DATA);
        if (osName.length() == 0 || base64Salt.length() == 0 || base64CipheredPrk.length() == 0
            || base64Puk.length() == 0 || base64Address.length() == 0 || base64MAC.length() == 0)
            return false;

        String mergedWalletData = versionInfo + osName + base64Salt + iterationCount + base64CipheredPrk + base64Puk + base64Address;
        byte[] salt = Base64.decode(base64Salt, Base64.NO_WRAP);
        byte[] mergedSaltAndPassword = getMergedByteArray(salt, psw.getBytes());
        String hashAlg = getValuesInPreferences(MoaPreferences.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlg.length() == 0)
            return false;

        byte[] hmacKey = hashDigest(hashAlg, mergedSaltAndPassword);
        String macAlg = getValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_ALGORITHM);
        if (macAlg.length() == 0)
            return false;
        byte[] macData = hmacDigest(macAlg, mergedWalletData.getBytes(), hmacKey);
        String newMacDataBase58 = Base64.encodeToString(macData, Base64.NO_WRAP);
        return base64MAC.equals(newMacDataBase58);
    }

    private byte[] getDecryptedPrivateKey(String psw) {
        byte[] privateKey = {0, };
        String lastEncryptedPrk = getValuesInPreferences(MoaPreferences.KEY_WALLET_CIPHERED_DATA);
        if (lastEncryptedPrk.length() == 0)
            return privateKey;

        int cipherMode = Cipher.DECRYPT_MODE;
        byte[] decode = Base64.decode(lastEncryptedPrk, Base64.NO_WRAP);
        byte[] firstEncryptedPrk = getRSAData(cipherMode, decode);
        privateKey = getPBKDF2Data(cipherMode, psw, firstEncryptedPrk);
        return privateKey;
    }

    private byte[] generateSignedData(String algorithm, PrivateKey privateKey, byte[] targetData) {
        byte[] resultData;
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(targetData);
            resultData = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[Wallet][generateSignedData] Failed to get sign data");
            throw new RuntimeException("Failed to get sign data", e);
        }
        return resultData;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final Wallet instance = new Wallet();
    }
}