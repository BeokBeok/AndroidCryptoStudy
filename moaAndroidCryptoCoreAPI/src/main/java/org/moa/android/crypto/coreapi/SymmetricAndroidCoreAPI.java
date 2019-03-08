package org.moa.android.crypto.coreapi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricAndroidCoreAPI {
    private Cipher cipher = null;
    private IvParameterSpec ivSpec = null;
    private SecretKeySpec keySpec = null;
    private String modeType = "";

    public SymmetricAndroidCoreAPI(String CryptonameModePadType, byte[] ivBytes, byte[] keyBytes) {
        try {
            final StringTokenizer stringTokenizer = new StringTokenizer(CryptonameModePadType, "/");
            final String cryptoAlgName = stringTokenizer.nextToken();
            modeType = stringTokenizer.nextToken();
            cipher = Cipher.getInstance(CryptonameModePadType);
            int blockSize = cipher.getBlockSize();
            int keySize = keyBytes.length;

            if (blockSize != keySize && blockSize + 8 != keySize && blockSize + 16 != keySize)
                throw new RuntimeException("Invalid key size error -> using 128/192/256bit");

            keySpec = new SecretKeySpec(keyBytes, cryptoAlgName);
            if (!modeType.equals("ECB"))
                ivSpec = new IvParameterSpec(ivBytes);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException("[*] --- Error message : " + e.getMessage());
        }
    }

    public synchronized byte[] symmetricEncryptData(byte[] data) {
        try {
            if (modeType.equals("ECB"))
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(data);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("[*] --- Error message : " + e.getMessage());
        }
    }

    public synchronized byte[] symmetricDecryptData(byte[] data) {
        try {
            if (modeType.equals("ECB"))
                cipher.init(Cipher.DECRYPT_MODE, keySpec);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(data);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("[*] --- Error message : " + e.getMessage());
        }
    }
}
