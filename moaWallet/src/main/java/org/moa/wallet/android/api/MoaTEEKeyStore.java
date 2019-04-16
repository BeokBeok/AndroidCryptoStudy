package org.moa.wallet.android.api;

public interface MoaTEEKeyStore {
    String PROVIDER = "AndroidKeyStore";
    String ALIAS_WALLET = "MoaWalletEncDecKeyPair";

    void initKeyStore();

    void generateKey();
}
