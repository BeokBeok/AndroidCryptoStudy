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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Properties;

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
    private SharedPreferences walletPref;
    private String savedFilePath;
    private KeyStore keyStore;

    private WalletManager() {
        initKeyStore();
        initProperties();
        generateKey();
    }

    static WalletManager getInstance() {
        return Singleton.instance;
    }

    void init(Context context) {
        this.context = context;
        String prefName = "walletPref";
        this.walletPref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        this.savedFilePath = context.getApplicationContext().getFilesDir().getPath() + "/";
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

    }

    @Override
    public String getValuesInPreference(String key) {
        return null;
    }

    boolean existFile() {
        final String walletFileName = walletPref.getString("Wallet.FileName", null);
        if (walletFileName == null)
            return false;
        File walletFile = new File(savedFilePath + walletFileName);
        boolean existFile = walletFile.exists();
        if (walletFile.exists()) {
            final byte[] content = readFileData(walletFileName);
            if (content.length == 0)
                existFile = false;
        }
        return existFile;
    }

    List<String> generateRequiredData(String password) {
        List<String> requiredWalletData = new ArrayList<>();

        byte[][] walletKeyPair = generateKeyPair();
        if (walletKeyPair.length == 0)
            return null;

        byte[][] saltPassword = new byte[2][];
        saltPassword[0] = generateSalt();
        saltPassword[1] = password.getBytes();

        byte[][] walletAddress = new byte[2][];
        walletAddress[0] = generateAddressCreatedWithPrivateKey(walletKeyPair[0]);
        walletAddress[1] = generateAddressCreatedWithPublicKey(walletKeyPair[1]);

        final byte[][] pbeKeyPair = getEncryptPBEKeyPair(walletKeyPair, password, saltPassword[0]);
        final String base64PbePrk = Base64.encodeToString(pbeKeyPair[0], Base64.NO_WRAP);
        final byte[] rsaWithPbePrk = getEncryptContent(base64PbePrk);
        if (rsaWithPbePrk == null)
            return null;
        walletKeyPair[0] = new byte[rsaWithPbePrk.length];
        walletKeyPair[0] = rsaWithPbePrk;

        requiredWalletData.add(MoaBase58.encode(walletKeyPair[0]));
        requiredWalletData.add(MoaBase58.encode(walletKeyPair[1]));
        requiredWalletData.add(MoaBase58.encode(saltPassword[0]));
        requiredWalletData.add(MoaBase58.encode(saltPassword[1]));
        requiredWalletData.add(MoaBase58.encode(walletAddress[0]));
        requiredWalletData.add(MoaBase58.encode(walletAddress[1]));
        return requiredWalletData;
    }

    void createFile(List<String> requiredWalletData) {
        if (existFile())
            return;

        try {
            String walletFileName = walletPref.getString("Wallet.FileName", null);
            if (walletFileName == null)
                return;
            FileWriter fileWriter = new FileWriter(new File(savedFilePath + walletFileName));
            String walletInfo = generateDataForm(requiredWalletData);
            fileWriter.write(walletInfo);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            Log.d("MoaLib", "[WalletManager][createFile] Failed to create wallet file");
            throw new RuntimeException("Failed to create wallet file", e);
        }
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

        final String signatureAlgorithm = walletPref.getString("Signature.Alg", null);
        final String keyPairAlgorithm = walletPref.getString("ECC.Alg", null);
        if (signatureAlgorithm == null || keyPairAlgorithm == null)
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
        if (!existFile())
            return null;
        final Properties properties = getPropertiesInstance();
        if (properties == null)
            return null;

        final String walletPukBase58 = properties.getProperty("Wallet.PublicKey");
        final String keyPairAlgorithm = walletPref.getString("ECC.Alg", null);
        if (walletPukBase58.length() == 0 || keyPairAlgorithm == null)
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

    String getContent() {
        final String walletFileName = walletPref.getString("Wallet.FileName", null);
        if (walletFileName == null)
            return "";
        File walletFile = new File(savedFilePath + walletFileName);
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(walletFile))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line);
                stringBuilder.append("\n");
            }
        } catch (IOException e) {
            Log.d("MoaLib", "[WalletManager][getContent] failed to get wallet content");
            throw new RuntimeException("Failed to get wallet content", e);
        }
        return stringBuilder.toString();
    }

    private void initProperties() {
        final SharedPreferences.Editor editor = walletPref.edit();
        editor.putInt("Version.Info", 1);
        editor.putString("Symmetric.Alg", "PBEwithSHAAND3-KEYTRIPLEDES-CBC");
        editor.putInt("Symmetric.KeySize", 192);
        editor.putString("Hash.Alg", "SHA256");
        editor.putString("Signature.Alg", "SHA256withECDSA");
        editor.putString("ECC.Alg", "EC");
        editor.putString("ECC.Curve", "secp256r1");
        editor.putString("MAC.Alg", "HmacSHA256");
        editor.putInt("Iteration.Count", 8192);
        editor.putString("Wallet.FileName", "moaWallet.dat");
        editor.apply();
    }

    private byte[] readFileData(String fileName) {
        byte[] content;
        try {
            File file = new File(savedFilePath + fileName);
            content = new byte[(int) file.length()];
            FileInputStream fileInputStream = new FileInputStream(file);
            final int length = fileInputStream.read(content);
            if (length == 0) {
                Log.d("MoaLib", "[WalletManager][readFileData] Content is empty");
                return content;
            }
            fileInputStream.close();
        } catch (IOException e) {
            Log.d("MoaLib", "[WalletManager][readFileData] failed to read file");
            throw new RuntimeException("Failed to read file", e);
        }
        return content;
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[64];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[][] generateKeyPair() {
        final String keyPairAlgorithm = walletPref.getString("ECC.Alg", null);
        final String standardName = walletPref.getString("ECC.Curve", null);
        byte[][] walletKeyPair = new byte[2][];

        if (keyPairAlgorithm == null || standardName == null)
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
        final int iterationCount = walletPref.getInt("Iteration.Count", 0);
        final int keySize = walletPref.getInt("Symmetric.KeySize", 0);
        final String secretKeyAlgorithm = walletPref.getString("Symmetric.Alg", null);
        byte[][] pbeKeyPair = new byte[2][];
        if (iterationCount == 0 || keySize == 0 || secretKeyAlgorithm == null)
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
        final String hashAlgorithm = walletPref.getString("Hash.Alg", null);
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

    private byte[] generateAddressCreatedWithPrivateKey(byte[] privateKey) {
        byte[] walletAddress = {0,};
        final String hashAlgorithm = walletPref.getString("Hash.Alg", null);
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

    private String generateDataForm(List<String> requiredWalletData) {
        String walletInfo = "";
        if (requiredWalletData.size() != 6)
            return walletInfo;

        final String versionInfo = String.valueOf(walletPref.getInt("Version.Info", 0));
        final String osInfo = System.getProperty("os.name");
        final String salt = requiredWalletData.get(2);
        final String iterationCount = String.valueOf(walletPref.getInt("Iteration.Count", 0));
        final String rsaWithPbePrk = requiredWalletData.get(0);
        final String publicKey = requiredWalletData.get(1);
        final String walletAddressMadeInPuk = requiredWalletData.get(4);

        final String targetMacData = versionInfo + osInfo + salt + iterationCount + rsaWithPbePrk + publicKey + walletAddressMadeInPuk;
        final String password = requiredWalletData.get(3);
        final String macData = generateMACData(salt, password, targetMacData);

        walletInfo = "Version.Info=" + versionInfo + "\n" +
                "OS.Info=" + osInfo + "\n" +
                "Salt.Value=" + salt + "\n" +
                "Iteration.Count=" + iterationCount + "\n" +
                "Ciphered.Data=" + rsaWithPbePrk + "\n" +
                "Wallet.PublicKey=" + publicKey + "\n" +
                "Wallet.Addr=" + walletAddressMadeInPuk + "\n" +
                "MAC.Data=" + macData;

        return walletInfo;
    }

    private String generateMACData(String salt, String password, String targetMacData) {
        String macData = "";
        final String hmacAlgorithm = walletPref.getString("MAC.Alg", null);
        final String hashAlgorithm = walletPref.getString("Hash.Alg", null);
        if (hmacAlgorithm == null || hashAlgorithm == null)
            return macData;
        final byte[] saltPassword = getMergedByteArray(MoaBase58.decode(salt), MoaBase58.decode(password));
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
        if (!existFile())
            return false;

        Properties properties = getPropertiesInstance();
        if (properties == null)
            return false;
        final int versionInfo = Integer.parseInt(properties.getProperty("Version.Info"));
        final String osName = properties.getProperty("OS.Info");
        final String saltBase58 = properties.getProperty("Salt.Value");
        final int iterationCount = Integer.parseInt(properties.getProperty("Iteration.Count"));
        final String rsaWithPbePrkBase58 = properties.getProperty("Ciphered.Data");
        final String walletPukBase58 = properties.getProperty("Wallet.PublicKey");
        final String walletAddrBase58 = properties.getProperty("Wallet.Addr");
        final String macDataBase58 = properties.getProperty("MAC.Data");
        final String mergedWalletData = versionInfo + osName + saltBase58 + iterationCount + rsaWithPbePrkBase58 + walletPukBase58 + walletAddrBase58;
        final byte[] salt = MoaBase58.decode(saltBase58);
        final byte[] mergedSaltAndPassword = getMergedByteArray(salt, password.getBytes());
        final String hashAlgorithm = walletPref.getString("Hash.Alg", null);
        if (hashAlgorithm == null)
            return false;
        final byte[] hmacKey = DigestAndroidCoreAPI.hashDigest(hashAlgorithm, mergedSaltAndPassword);
        final String macAlgorithm = walletPref.getString("MAC.Alg", null);
        if (macAlgorithm == null)
            return false;
        final byte[] macData = DigestAndroidCoreAPI.hmacDigest(macAlgorithm, mergedWalletData.getBytes(), hmacKey);
        final String newMacDataBase58 = MoaBase58.encode(macData);
        checkWalletMacData = macDataBase58.equals(newMacDataBase58);

        return checkWalletMacData;
    }

    private Properties getPropertiesInstance() {
        Properties properties;
        try {
            final String walletFileName = walletPref.getString("Wallet.FileName", null);
            if (walletFileName == null)
                return null;
            File walletFile = new File(savedFilePath + walletFileName);
            properties = new Properties();
            properties.load(new FileInputStream(walletFile.getPath()));
        } catch (IOException e) {
            Log.d("MoaLib", "[WalletManager][getPropertiesInstance] Failed to get properties");
            throw new RuntimeException("Failed to get properties", e);
        }
        return properties;
    }

    private byte[] getDecryptedPrivateKey(String password) {
        byte[] privateKey = {0,};

        final String walletFileName = walletPref.getString("Wallet.FileName", null);
        final int keySize = walletPref.getInt("Symmetric.KeySize", 0);
        final String secretKeyAlgorithm = walletPref.getString("Symmetric.Alg", null);
        if (walletFileName == null || keySize == 0 || secretKeyAlgorithm == null)
            return privateKey;

        final Properties properties = getPropertiesInstance();
        if (properties == null)
            return privateKey;

        final String rsaWithPbePrkBase58 = properties.getProperty("Ciphered.Data");
        final String saltBase58 = properties.getProperty("Salt.Value");
        final int iterationCount = Integer.parseInt(properties.getProperty("Iteration.Count"));
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