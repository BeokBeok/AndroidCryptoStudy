package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.DigestAndroidCoreAPI;
import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.android.crypto.coreapi.RIPEMD160;

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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.x500.X500Principal;

class WalletManager implements KeyStoreTEEManager, SharedPreferencesManager {
    private final String keyAlias = KeyStoreTEEManager.ALIAS_WALLET;
    private final String transformation = "RSA/ECB/PKCS1Padding";
    private Context context;
    private KeyStore keyStore;

    private WalletManager() {
        initKeyStore();
    }

    static WalletManager getInstance() {
        return Singleton.instance;
    }

    void init(Context context) {
        this.context = context;
        initProperties();
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();
        } catch (KeyStoreException e) {
            Log.d("MoaLib", "[WalletManager] failed to check key alias");
        }
    }

    @Override
    public void initKeyStore() {
        try {
            this.keyStore = KeyStore.getInstance(KeyStoreTEEManager.PROVIDER);
            this.keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d("MoaLib", "[WalletManager][initKeyStore] failed to init keystore");
            throw new RuntimeException("Failed to init keystore", e);
        }
    }

    @Override
    public void generateKey() {
        final String keyAlgorithm = "RSA";
        final Calendar startData = Calendar.getInstance();
        final Calendar endData = Calendar.getInstance();
        endData.add(Calendar.YEAR, 25);

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, KeyStoreTEEManager.PROVIDER);
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
            Log.d("MoaLib", "[WalletManager][generateKey] Failed to create wallet key pair");
            throw new RuntimeException("Failed to create wallet key pair", e);
        }
    }

    @Override
    public void setValuesInPreference(String key, String value) {
        SharedPreferences pref = context.getSharedPreferences(SharedPreferencesManager.PREFNAME_WALLET, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, value);
        editor.apply();
    }

    @Override
    public String getValuesInPreference(String key) {
        SharedPreferences pref = context.getSharedPreferences(SharedPreferencesManager.PREFNAME_WALLET, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null)
            value = "";
        return value;
    }

    boolean existPreference() {
        String walletAddress = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ADDRESS);
        return walletAddress.length() > 0;
    }

    void generateInfo(String password) {
        byte[][] walletKeyPair = generateKeyPair();
        if (walletKeyPair.length == 0)
            return;
        byte[] walletAddressCreatedPuk = generateAddressCreatedWithPublicKey(walletKeyPair[1]);
        final byte[] salt = generateSalt();
        final byte[][] pbeKeyPair = getEncryptPBEKeyPair(walletKeyPair, password, salt);
        if (pbeKeyPair.length == 0)
            return;
        final String base64PbePrk = Base64.encodeToString(pbeKeyPair[0], Base64.NO_WRAP);
        final byte[] rsaWithPbePrk = getEncryptContent(base64PbePrk);
        if (rsaWithPbePrk == null)
            return;

        final String versionInfo = String.valueOf(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_VERSION_INFO));
        final String osInfo = System.getProperty("os.name");
        final String saltBase58 = MoaBase58.encode(salt);
        final String iterationCount = String.valueOf(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ITERATION_COUNT));
        final String rsaWithPbePrkBase58 = MoaBase58.encode(rsaWithPbePrk);
        final String publicKeyBase58 = MoaBase58.encode(walletKeyPair[1]);
        final String walletAddressCreatedPukBase58 = MoaBase58.encode(walletAddressCreatedPuk);
        final String targetMacData = versionInfo + osInfo + saltBase58 + iterationCount + rsaWithPbePrkBase58 + publicKeyBase58 + walletAddressCreatedPukBase58;
        final String macDataBase58 = generateMACData(saltBase58, password, targetMacData);

        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_OS_INFO, osInfo);
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_SALT, saltBase58);
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_CIPHERED_DATA, rsaWithPbePrkBase58);
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_PUBLIC_KEY, publicKeyBase58);
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_ADDRESS, walletAddressCreatedPukBase58);
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_MAC_DATA, macDataBase58);
    }

    byte[] generateSignedTransactionData(String transaction, String password) {
        byte[] signData = {0,};
        if (!checkMACData(password))
            return signData;

        final byte[] privateKeyBytes = getDecryptedPrivateKey(password);
        if (privateKeyBytes == null)
            return signData;
        if (privateKeyBytes.length == 0)
            return signData;

        final String signatureAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SIGNATURE_ALGIROTHM);
        final String keyPairAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_ALGORITHM);
        if (signatureAlgorithm.length() == 0 || keyPairAlgorithm.length() == 0)
            return signData;
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            signData = generateSignedData(signatureAlgorithm, privateKey, transaction.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[WalletManager][generateSignedTransactionData] failed to get signed transaction data");
            throw new RuntimeException("Failed to get signed transaction data", e);
        }
        return signData;
    }

    PublicKey getPublicKey() {
        if (!existPreference())
            return null;

        final String walletPukBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_PUBLIC_KEY);
        final String keyPairAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_ALGORITHM);
        if (walletPukBase58.length() == 0 || keyPairAlgorithm.length() == 0)
            return null;

        final byte[] publicKeyBytes = MoaBase58.decode(walletPukBase58);
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.d("MoaLib", "[WalletManager][getPublicKey] failed to get wallet public key");
            throw new RuntimeException("Failed to get wallet public key", e);
        }
    }

    private void initProperties() {
        if (getValuesInPreference(SharedPreferencesManager.KEY_WALLET_VERSION_INFO).length() > 0)
            return;
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_VERSION_INFO, "1");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_ALGORITHM, "PBEwithSHAAND3-KEYTRIPLEDES-CBC");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_KEY_SIZE, "192");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_HASH_ALGORITHM, "SHA256");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_SIGNATURE_ALGIROTHM, "SHA256withECDSA");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_ALGORITHM, "EC");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_CURVE, "secp256r1");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_MAC_ALGORITHM, "HmacSHA256");
        setValuesInPreference(SharedPreferencesManager.KEY_WALLET_ITERATION_COUNT, "8192");
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[64];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[][] generateKeyPair() {
        final String keyPairAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_ALGORITHM);
        final String standardName = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ECC_CURVE);
        byte[][] walletKeyPair = new byte[2][];
        if (keyPairAlgorithm.length() == 0 || standardName.length() == 0)
            return walletKeyPair;
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm);
            final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(standardName);
            keyPairGenerator.initialize(ecGenParameterSpec);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            walletKeyPair[0] = keyPair.getPrivate().getEncoded();
            walletKeyPair[1] = keyPair.getPublic().getEncoded();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[WalletManager][generateKeyPair] Failed to get wallet key pair");
            throw new RuntimeException("Failed to get wallet key pair", e);
        }
        return walletKeyPair;
    }

    private byte[][] getEncryptPBEKeyPair(byte[][] keyPair, String password, byte[] salt) {
        final int iterationCount = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ITERATION_COUNT));
        final int keySize = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_KEY_SIZE));
        final String secretKeyAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_ALGORITHM);
        byte[][] pbeKeyPair = new byte[2][];
        if (iterationCount == 0 || keySize == 0 || secretKeyAlgorithm.length() == 0)
            return pbeKeyPair;
        try {
            final Cipher cipher = Cipher.getInstance(secretKeyAlgorithm);
            final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize);
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, iterationCount);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
            pbeKeyPair[0] = cipher.doFinal(keyPair[0]);
            pbeKeyPair[1] = cipher.doFinal(keyPair[1]);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            Log.d("MoaLib", "[WalletManager][getEncryptPBEKeyPair] Failed to get PBE wallet key pair");
            throw new RuntimeException("Failed to get PBE wallet key pair", e);
        }
        return pbeKeyPair;
    }

    private byte[] generateAddressCreatedWithPublicKey(byte[] publicKey) {
        byte[] walletAddress = {0,};
        final String hashAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlgorithm == null)
            return walletAddress;

        int prefixSize = 1;
        byte[] hashPuk = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, publicKey);
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
        final String hashAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlgorithm == null)
            return walletAddress;

        int prefixSize = 1;
        byte[] hashPrk = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, privateKey);
        byte[] dualHashPrk = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, hashPrk);
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

    private String generateMACData(String salt, String password, String targetMacData) {
        String macData = "";
        final String hmacAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_MAC_ALGORITHM);
        final String hashAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_HASH_ALGORITHM);
        if (hmacAlgorithm == null || hashAlgorithm == null)
            return macData;
        final byte[] saltPassword = getMergedByteArray(MoaBase58.decode(salt), password.getBytes());
        final byte[] hmacKey = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, saltPassword);
        byte[] macDataBytes = DigestAndroidCoreAPI.hmacDigest(hmacAlgorithm, targetMacData.getBytes(), hmacKey);
        return MoaBase58.encode(macDataBytes);
    }

    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        byte[] targetByteArr = new byte[first.length + second.length];
        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);
        return targetByteArr;
    }

    private byte[] getEncryptContent(String content) {
        byte[] resultData;
        try {
            if (!keyStore.containsAlias(keyAlias))
                generateKey();

            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            if (publicKey == null) {
                Log.d("MoaLib", "[WalletManager][getEncryptRSACipher] publicKey key is null");
                return null;
            }
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] targetByte = Base64.decode(content, Base64.NO_WRAP);
            resultData = cipher.doFinal(targetByte);
        } catch (BadPaddingException | IllegalBlockSizeException | KeyStoreException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidKeyException e) {
            Log.d("MoaLib", "[WalletManager][getEncryptContent] Failed to get encrypted content");
            throw new RuntimeException("Failed to get encrypted content", e);
        }
        return resultData;
    }

    private boolean checkMACData(String password) {
        boolean checkWalletMacData;
        if (!existPreference())
            return false;
        final int versionInfo = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_VERSION_INFO));
        final String osName = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_OS_INFO);
        final String saltBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SALT);
        final int iterationCount = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ITERATION_COUNT));
        final String rsaWithPbePrkBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_CIPHERED_DATA);
        final String walletPukBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_PUBLIC_KEY);
        final String walletAddrBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ADDRESS);
        final String macDataBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_MAC_DATA);
        final String mergedWalletData = versionInfo + osName + saltBase58 + iterationCount + rsaWithPbePrkBase58 + walletPukBase58 + walletAddrBase58;
        final byte[] salt = MoaBase58.decode(saltBase58);
        final byte[] mergedSaltAndPassword = getMergedByteArray(salt, password.getBytes());
        final String hashAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_HASH_ALGORITHM);
        if (hashAlgorithm == null)
            return false;
        final byte[] hmacKey = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, mergedSaltAndPassword);
        final String macAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_MAC_ALGORITHM);
        if (macAlgorithm == null)
            return false;
        final byte[] macData = DigestAndroidCoreAPI.hmacDigest(macAlgorithm, mergedWalletData.getBytes(), hmacKey);
        final String newMacDataBase58 = MoaBase58.encode(macData);
        checkWalletMacData = macDataBase58.equals(newMacDataBase58);

        return checkWalletMacData;
    }

    private byte[] getDecryptedPrivateKey(String password) {
        byte[] privateKey = {0,};
        final int keySize = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_KEY_SIZE));
        final String secretKeyAlgorithm = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SYMMETRIC_ALGORITHM);
        if (keySize == 0 || secretKeyAlgorithm.length() == 0)
            return privateKey;

        final String rsaWithPbePrkBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_CIPHERED_DATA);
        final String saltBase58 = getValuesInPreference(SharedPreferencesManager.KEY_WALLET_SALT);
        final int iterationCount = Integer.parseInt(getValuesInPreference(SharedPreferencesManager.KEY_WALLET_ITERATION_COUNT));
        if (rsaWithPbePrkBase58.length() == 0 || saltBase58.length() == 0 || iterationCount == 0)
            return null;

        final byte[] rsaWithPbePrk = MoaBase58.decode(rsaWithPbePrkBase58);
        final Cipher rsaCipher = getDecryptRSACipher();
        if (rsaCipher == null)
            return null;
        try {
            final byte[] pbePrk = rsaCipher.doFinal(rsaWithPbePrk);
            // Decrypt PBE
            final Cipher pbeCipher = Cipher.getInstance(secretKeyAlgorithm);
            byte[] salt = MoaBase58.decode(saltBase58);
            final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize);
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec algorithmParameterSpec = new PBEParameterSpec(salt, iterationCount);
            pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec);
            privateKey = pbeCipher.doFinal(pbePrk);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            Log.d("MoaLib", "[WalletManager][getDecryptedPrivateKey] Failed to get decrypted wallet private key");
            throw new RuntimeException("Failed to get decrypted wallet private key", e);
        }
        return privateKey;
    }

    private Cipher getDecryptRSACipher() {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            if (privateKey == null) {
                Log.d("MoaLib", "[WalletManager][getDecryptRSACipher] private key is null");
                return null;
            }
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnrecoverableKeyException
                | KeyStoreException | InvalidKeyException e) {
            Log.d("MoaLib", "[WalletManager][getDecryptRSACipher] failed to cipher init");
            throw new RuntimeException("Failed to cipher init", e);
        }
        return cipher;
    }

    private byte[] generateSignedData(String algorithm, PrivateKey privateKey, byte[] targetData) {
        byte[] resultData;
        try {
            final Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(targetData);
            resultData = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.d("MoaLib", "[WalletManager][generateSignedData] Failed to get sign data");
            throw new RuntimeException("Failed to get sign data", e);
        }
        return resultData;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final WalletManager instance = new WalletManager();
    }
}