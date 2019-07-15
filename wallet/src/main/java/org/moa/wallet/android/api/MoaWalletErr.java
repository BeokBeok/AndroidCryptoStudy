package org.moa.wallet.android.api;

public enum MoaWalletErr {
    RESTORE_PASSWORD_NOT_VERIFY("1142");

    private String type;

    MoaWalletErr(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
