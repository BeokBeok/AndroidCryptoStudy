package org.moa.auth.userauth.android.api;

public enum KeyStoreAlias {
    CONTROL_INFO("MoaControlInfo"),
    FINGER_KEY_PAIR("MoaFingerKeyPair"),
    USER_AUTH_TOKEN("MoaUserAuthToken"),
    WALLET_KEY_PAIR("MoaWalletKeyPair"),
    WALLET_ADDRESS("MoaWalletAddress");

    private String alias;

    KeyStoreAlias(String alias) {
        this.alias = alias;
    }

    public String getAlias() {
        return alias;
    }
}
