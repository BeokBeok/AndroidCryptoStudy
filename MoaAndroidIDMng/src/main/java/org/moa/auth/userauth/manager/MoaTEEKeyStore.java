package org.moa.auth.userauth.manager;

interface MoaTEEKeyStore {
    String PROVIDER = "AndroidKeyStore";
    String ALIAS_AUTO_INFO = "MoaAutoInfo";
    String ALIAS_FINGERPRINT = "MoaFingerKeyPair";
    String ALIAS_AUTH_TOKEN = "MoaUserAuthToken";
    String ALIAS_WALLET = "MoaWalletEncDecKeyPair";

    void initKeyStore();

    void generateKey();
}
