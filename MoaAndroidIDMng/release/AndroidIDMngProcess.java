package org.moa.auth.userauth.android.api;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.telephony.TelephonyManager;
import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AndroidIDMngProcess {
    private final String FILENAME_IDMANAGER = "androidIDManager.dat";
    private final String FILENAME_AUTHTOKEN = "androidAuthToken.dat";
    private final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private final String TRANSFORMATION = "AES/GCM/NoPadding";
    private final String ENCODE_FORMAT = "UTF-8";

    private Activity activity;
    private String savedFilePath;
    private byte[] idManagerIV = {0, };
    private byte[] authTokenIV = {0, };
    private KeyStore keyStore;

    /**
     * Constructor
     * @param activity current activity
     */
    public AndroidIDMngProcess(Activity activity) {
        this.activity = activity;
        this.savedFilePath = activity.getApplicationContext().getFilesDir().getPath();
        try {
            this.keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get instance keystore", e);
        }
    }

    /**
     * Create non member pin and write file created data
     */
    public void createNonMemberPinAndFile() {
        String nonMemberPinInfo = getNonMemberPinInfo();
        if (nonMemberPinInfo.length() < 1) {
            Log.d("MoaLib", "non member pin value is empty");
            return;
        }
        createFile(FILENAME_IDMANAGER, nonMemberPinInfo);
    }

    /**
     * exist control info file ("androidIDManager.dat")
     * @return  true : control info file exist
     *          false : control info file not exist
     */
    public boolean existControlInfoFile() {
        File file = new File(savedFilePath + FILENAME_IDMANAGER);
        return file.exists();
    }

    /**
     * Get fingerprint register message
     * Require above API 23(M)
     * @param ecdsaCurve algorithm param spec (ex, secp256r1)
     * @param ecdsaSignAlgSuite signature algorithm (ex, SHA256withECDSA)
     * @param base64AuthToken auth token data
     * @return generated fingerprint register message
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(String ecdsaCurve, String ecdsaSignAlgSuite, String base64AuthToken) {
        if (!existKey(KeyStoreAlias.FINGER_KEY_PAIR.getAlias()))
            generateECDSAKeyPair(KeyStoreAlias.FINGER_KEY_PAIR.getAlias(), ecdsaCurve);

        saveAuthToken(ecdsaCurve, base64AuthToken);

        byte[] resultData;
        try {
            PublicKey publicKey = keyStore.getCertificate(KeyStoreAlias.FINGER_KEY_PAIR.getAlias()).getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KeyStoreAlias.FINGER_KEY_PAIR.getAlias(), null);

            byte[] authToken = Base64.decode(base64AuthToken, Base64.NO_WRAP);
            byte[] combineAuthTokenWithPublicKey = getMergedByteArray(authToken, publicKey.getEncoded());
            resultData = getSignData(ecdsaSignAlgSuite, privateKey, combineAuthTokenWithPublicKey);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to get register signature data", e);
        }
        return resultData;
    }

    /**
     * Get fingerprint login message
     * @param ecdsaSignAlgSuite signature algorithm (ex, SHA256withECDSA)
     * @param base64NonceOTP nonceOTP data
     * @param base64AuthToken auth token data
     * @return generated fingerprint login message
     */
    public byte[] getFingerprintLoginECDSASign(String ecdsaSignAlgSuite, String base64NonceOTP, String base64AuthToken) {
        byte[] resultData = {0,};
        if (!existKey(KeyStoreAlias.FINGER_KEY_PAIR.getAlias()))
            return resultData;

        byte[] nonceOTP = Base64.decode(base64NonceOTP, Base64.NO_WRAP);
        byte[] authToken = Base64.decode(base64AuthToken, Base64.NO_WRAP);
        byte[] combineNonceOTPWithAuthToken = getMergedByteArray(nonceOTP, authToken);
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KeyStoreAlias.FINGER_KEY_PAIR.getAlias(), null);
            resultData = getSignData(ecdsaSignAlgSuite, privateKey, combineNonceOTPWithAuthToken);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to get login signature data", e);
        }
        return resultData;
    }

    /**
     * Get control info data ("androidIDManager.dat")
     * @return control info data saved file
     */
    public String getControlInfoData() {
        return getDecryptContent(FILENAME_IDMANAGER);
    }

    /**
     * Get auth token data ("androidAuthToken.dat")
     * @return auth token data saved file
     */
    public String getAuthTokenData() {
        return getDecryptContent(FILENAME_AUTHTOKEN);
    }

    /**
     * Set control info data at file ("androidIDManager.dat")
     * @param data control info data
     */
    public void setControlInfoData(String data) {
        if (data.length() < 1) {
            Log.d("MoaLib", "data not validate");
            return;
        }

        String token = "$";
        StringTokenizer stringTokenizer = new StringTokenizer(data, token);
        ArrayList<String> controlInfoArray = new ArrayList<>();
        while (stringTokenizer.hasMoreElements()) {
            controlInfoArray.add((String)stringTokenizer.nextElement());
        }
        if (controlInfoArray.size() != 4) {
            Log.d("MoaLib", "data not validate");
            return;
        }

        createFile(FILENAME_IDMANAGER, data);
    }

    /**
     * Create unique device id (device id || sim serial number || android id)
     * @return unique device id
     */
    @SuppressLint({"MissingPermission", "HardwareIds"})
    private String getUniqueDeviceID() {
        final TelephonyManager telephonyManager = (TelephonyManager) activity.getSystemService(Context.TELEPHONY_SERVICE);
        String result = "";
        if (telephonyManager == null)
            return "";

        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
            String deviceID;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                deviceID = telephonyManager.getImei();
            else
                deviceID = telephonyManager.getDeviceId();

            final String simSerialNumber = telephonyManager.getSimSerialNumber();
            final String androidID = Settings.Secure.getString(activity.getContentResolver(), Settings.Secure.ANDROID_ID);
            UUID deviceUuid = new UUID(androidID.hashCode(), ((long)deviceID.hashCode() << 32 | simSerialNumber.hashCode()));
            result = deviceUuid.toString();
        } else {
            ActivityCompat.requestPermissions(activity, new String[]{Manifest.permission.READ_PHONE_STATE},0);
        }
        return result;
    }

    /**
     * Create non member pin id
     * @return non member pin id
     */
    private String getNonMemberPinInfo() {
        String algorithmName = "SHA256";
        String providerName = "BC";
        String nonMemberType = MemberType.NONMEMBER.getType();
        String tokenChar = "$";

        String result;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmName, providerName);
            String uniqueDeviceID = getUniqueDeviceID();
            if (uniqueDeviceID.length() < 1)
                return "";
            messageDigest.update(uniqueDeviceID.getBytes());
            byte[] nonMemberPin = messageDigest.digest();
            result = nonMemberType.concat(tokenChar).concat(Base64.encodeToString(nonMemberPin, Base64.NO_WRAP));
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to HashDigest", e);
        }
        return result;
    }

    /**
     * Get secret key
     * Require above API 23(M)
     * @return secret key
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey getSecretKey(String alias) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            final KeyGenParameterSpec keyGenParameterSpec =
                    new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build();

            keyGenerator.init(keyGenParameterSpec);
            return keyGenerator.generateKey();
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to get secret key", e);
        }
    }

    /**
     * set initialization vector
     * @param alias key alias
     * @param iv initialization vector
     */
    private void setInitializationVector(String alias, byte[] iv) {
        if (alias.equals(KeyStoreAlias.CONTROL_INFO.getAlias()))
            this.idManagerIV = iv;
        else if (alias.equals(KeyStoreAlias.USER_AUTH_TOKEN.getAlias()))
            this.authTokenIV = iv;
    }

    /**
     * Get encrypt content
     * Require above API 23(M)
     * @param content encrypted data
     * @return encrypted content
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private byte[] getEncryptContent(String keyAlias, String content) {
        byte[] encryption = {0,};

        if (keyAlias.length() < 1 || content.length() < 1)
            return encryption;

        try {
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKey secretKey = getSecretKey(keyAlias);

            if (secretKey != null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                setInitializationVector(keyAlias, cipher.getIV());
                byte[] targetByte = content.getBytes(ENCODE_FORMAT);
                encryption = cipher.doFinal(targetByte);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException e) {
            throw new RuntimeException("Failed to get encrypted content", e);
        }
        return encryption;
    }

    /**
     * Create file
     * @param content
     * Reference getUniqueDeviceID Function
     */
    private void createFile(String fileName, String content) {
        try {
            String alias = getKeyAliasForFileName(fileName);
            byte[] encryptedData = getEncryptContent(alias, content);
            FileOutputStream fos = new FileOutputStream(savedFilePath + "/" + fileName);
            fos.write(encryptedData);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create file", e);
        }
    }

    /**
     * Get file name related key alias
     * @param fileName file name (include extension)
     * @return key alias related file name
     */
    private String getKeyAliasForFileName(String fileName) {
        if (fileName.length() < 1)
            return "";

        String keyAlias = "";
        if (fileName.equals(FILENAME_IDMANAGER))
            keyAlias = KeyStoreAlias.CONTROL_INFO.getAlias();
        else if (fileName.equals(FILENAME_AUTHTOKEN))
            keyAlias = KeyStoreAlias.USER_AUTH_TOKEN.getAlias();

        return keyAlias;
    }

    /**
     * Get gcm param spec for key alias
     * @param alias key store alias
     * @return gcm param spec
     */
    private GCMParameterSpec getGCMParamSpecForKeyAlias(String alias) {
        GCMParameterSpec spec = null;
        int initializationVectorLen = 128;
        if (alias.equals(KeyStoreAlias.CONTROL_INFO.getAlias()))
            spec = new GCMParameterSpec(initializationVectorLen, this.idManagerIV);
        else if (alias.equals(KeyStoreAlias.USER_AUTH_TOKEN.getAlias()))
            spec = new GCMParameterSpec(initializationVectorLen, this.authTokenIV);

        return spec;
    }

    /**
     * read file data written by byte type
     * @param fileName file name
     * @return byte type data
     */
    private byte[] readFileData(String fileName) {
        byte[] content = {0, };
        try {
            File file = new File(savedFilePath + "/" + fileName);
            content = new byte[(int) file.length()];
            FileInputStream fileInputStream = new FileInputStream(file);
            int length = fileInputStream.read(content);
            if (length < 1) {
                Log.d("MoaLib", "content read file is empty");
                return content;
            }
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    /**
     * Decrypt encrypted file data
     * @return decrypted content
     */
    private String getDecryptContent(String fileName) {
        String keyAlias = getKeyAliasForFileName(fileName);
        if (keyAlias.length() < 1) {
            Log.d("MoaLib", "key alias is empty");
            return "";
        }

        String result = "";
        try {
            keyStore.load(null);

            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec spec = getGCMParamSpecForKeyAlias(keyAlias);
            if (spec == null) {
                Log.d("MoaLib", "GCMParameter Spec is null");
                return "";
            }
            KeyStore.Entry keyStoreEntry = keyStore.getEntry(keyAlias, null);
            if (keyStoreEntry != null) {
                SecretKey secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null)).getSecretKey();
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            }

            byte[] content = readFileData(fileName);
            if (content.length > 1) {
                byte[] decryptData = cipher.doFinal(content);
                result = new String(decryptData, ENCODE_FORMAT);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException
                | NoSuchPaddingException | UnrecoverableEntryException | InvalidKeyException
                | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("Failed to get decrypt data", e);
        }
        return result;
    }

    /**
     * check key exist
     * @param keyAlias key store alias
     * @return  true : key exist
     *          false : key not exist
     */
    private boolean existKey(String keyAlias) {
        try {
            keyStore.load(null);
            Key key = keyStore.getKey(keyAlias, null);
            return (key != null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyStoreException e) {
            throw new RuntimeException("Failed to exist key", e);
        }
    }

    /**
     * Generate key pair related fingerprint
     * Require above API 23(M)
     * @param ecdsaCurve algorithm param spec (ex, secp256r1)
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateECDSAKeyPair(String keyAlias, String ecdsaCurve) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec(ecdsaCurve))
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(10)
                            .build()
            );
            keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to create key pair", e);
        }
    }

    /**
     * save auth token at file
     * @param ecdsaCurve algorithm param spec (ex, secp256r1)
     * @param authToken auth token data
     */
    private void saveAuthToken(String ecdsaCurve, String authToken) {
        if (!existKey(KeyStoreAlias.USER_AUTH_TOKEN.getAlias()))
            generateECDSAKeyPair(KeyStoreAlias.USER_AUTH_TOKEN.getAlias(), ecdsaCurve);

        createFile(FILENAME_AUTHTOKEN, authToken);
    }

    /**
     * Get merged byte array
     * @param first first merged byte array
     * @param second second merged byte array
     * @return merged byte array
     */
    private byte[] getMergedByteArray(byte[] first, byte[] second) {
        byte[] targetByteArr = new byte[first.length + second.length];

        System.arraycopy(first, 0, targetByteArr, 0, first.length);
        System.arraycopy(second, 0, targetByteArr, first.length, second.length);

        return targetByteArr;
    }

    /**
     * Get signed data
     * @param algorithm signature algorithm (ex, SHA256withECDSA)
     * @param privateKey private key data
     * @param targetData encrypted target data
     * @return signed data
     */
    private byte[] getSignData(String algorithm, PrivateKey privateKey, byte[] targetData) {
        byte[] resultData;
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(targetData);
            resultData = signature.sign();
        } catch(NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Failed to get sign data", e);
        }
        return resultData;
    }
}