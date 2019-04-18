package org.moa.auth.userauth.android.api;

public interface MoaTEEUsable {
    String PROVIDER = "AndroidKeyStore";
    String ALIAS_AUTO_INFO = "MoaAutoInfo";
    String ALIAS_FINGERPRINT = "MoaFingerKeyPair";
    String ALIAS_AUTH_TOKEN = "MoaUserAuthToken";

    void initKeyStore();

    void generateKey();
}
