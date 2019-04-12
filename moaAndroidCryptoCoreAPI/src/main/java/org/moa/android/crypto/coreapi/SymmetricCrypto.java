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

public class SymmetricCrypto {
    private Cipher cipher;
    private IvParameterSpec ivSpec;
    private SecretKeySpec keySpec;
    private String modeType;

    public SymmetricCrypto(String CryptoNameModePadType, byte[] ivBytes, byte[] keyBytes) {
        try {
            StringTokenizer stringTokenizer = new StringTokenizer(CryptoNameModePadType, "/");
            String cryptoAlgName = stringTokenizer.nextToken();
            modeType = stringTokenizer.nextToken();
            cipher = Cipher.getInstance(CryptoNameModePadType);
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

    public byte[] getSymmetricData(int mode, byte[] data) {
        byte[] result = {0, };
        if (data.length == 0)
            return result;
        try {
            if (modeType.equals("ECB"))
                cipher.init(mode, keySpec);

            cipher.init(mode, keySpec, ivSpec);
            result = cipher.doFinal(data);
            return result;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("[*] --- Error message : " + e.getMessage());
        }
    }
}
