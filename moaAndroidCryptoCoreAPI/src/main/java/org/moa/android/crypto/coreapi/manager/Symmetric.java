package org.moa.android.crypto.coreapi.manager;

import android.util.Log;

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

public class Symmetric {
    private Cipher cipher;
    private IvParameterSpec ivSpec;
    private SecretKeySpec keySpec;
    private String modeType;

    private Symmetric() {
    }

    public static Symmetric getInstance() {
        return Singleton.instance;
    }

    public void initSymmetric(String cryptoNameModePadType, byte[] ivBytes, byte[] keyBytes) {
        try {
            StringTokenizer stringTokenizer = new StringTokenizer(cryptoNameModePadType, "/");
            String cryptoAlgName = stringTokenizer.nextToken();
            modeType = stringTokenizer.nextToken();
            cipher = Cipher.getInstance(cryptoNameModePadType);
            int blockSize = cipher.getBlockSize();
            int keySize = keyBytes.length;

            if (blockSize != keySize && blockSize + 8 != keySize && blockSize + 16 != keySize) {
                Log.d("MoaLib", "[Symmetric]" + "Invalid key size error -> using 128/192/256bit");
                return;
            }

            keySpec = new SecretKeySpec(keyBytes, cryptoAlgName);
            if (!modeType.equals("ECB"))
                ivSpec = new IvParameterSpec(ivBytes);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            Log.d("MoaLib", "[Symmetric]" + e.getMessage());
        }
    }

    public byte[] getSymmetricData(int encOrDecMode, byte[] data) {
        byte[] result = {0, };
        if (data.length == 0)
            return result;
        try {
            if (modeType.equals("ECB"))
                cipher.init(encOrDecMode, keySpec);

            cipher.init(encOrDecMode, keySpec, ivSpec);
            result = cipher.doFinal(data);
            return result;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            Log.d("MoaLib", "[Symmetric][getSymmetricData]" + e.getMessage());
            return new byte[0];
        }
    }

    private static class Singleton {
        private static Symmetric instance = new Symmetric();
    }
}
