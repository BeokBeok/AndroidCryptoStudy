package org.moa.auth.userauth.android.api;

public enum MoaMember {
    NON_MEMBER(0x71, 0x80, 0x90),
    MEMBER_PIN(0x72, 0x81, 0x92),
    MEMBER_FINGER(0x72, 0x82, 0x92);

    private int memberType;
    private int authType;
    private int walletType;

    MoaMember(int memberType, int authType, int walletType) {
        this.memberType = memberType;
        this.authType = authType;
        this.walletType = walletType;
    }

    public int getMemberType() {
        return memberType;
    }

    public int getAuthType() {
        return authType;
    }

    public int getWalletType() {
        return walletType;
    }
}
