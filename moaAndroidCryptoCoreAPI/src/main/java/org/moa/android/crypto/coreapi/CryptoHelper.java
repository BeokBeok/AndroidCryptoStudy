package org.moa.android.crypto.coreapi;

import org.moa.android.crypto.coreapi.manager.MoaBase58;
import org.moa.android.crypto.coreapi.manager.PBKDF2;
import org.moa.android.crypto.coreapi.manager.RIPEMD160;
import org.moa.android.crypto.coreapi.manager.SymmetricCrypto;

public class CryptoHelper {
    private CryptoHelper() {
    }

    public static CryptoHelper getInstance() {
        return Singleton.instance;
    }

    public String encode58(byte[] input) {
        return MoaBase58.getInstance().encode(input);
    }

    public byte[] decode58(String input) {
        return MoaBase58.getInstance().decode(input);
    }

    public void initKDF(String hashAlg) {
        PBKDF2.getInstance().setHashAlg(hashAlg);
    }

    public byte[] generateKDF(byte[] password, byte[] salt, int iterations, int dkLen) {
        return PBKDF2.getInstance().kdfGen(password, salt, iterations, dkLen);
    }

    public byte[] getHashRIPEMD160(byte[] msg) {
        return RIPEMD160.getInstance().getHash(msg);
    }

    public void initSymmetricCrypto(String cryptoNameModePadType, byte[] ivBytes, byte[] keyBytes) {
        SymmetricCrypto.getInstance().initSymmetricCrypto(cryptoNameModePadType, ivBytes, keyBytes);
    }

    public byte[] getSymmetricData(int encOrDecMode, byte[] data) {
        return SymmetricCrypto.getInstance().getSymmetricData(encOrDecMode, data);
    }

    private static class Singleton {
        private static CryptoHelper instance = new CryptoHelper();
    }
}
