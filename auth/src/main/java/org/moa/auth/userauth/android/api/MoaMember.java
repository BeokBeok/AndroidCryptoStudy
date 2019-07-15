package org.moa.auth.userauth.android.api;

/**
 * 멤버 정보 (멤버 타입, 인증 타입, 지갑 타입)
 */
public enum MoaMember {
    /** 비회원 */
    NON_MEMBER(0x71, 0x80, 0x90),
    /** 회원 + PIN */
    MEMBER_PIN(0x72, 0x81, 0x92),
    /** 회원 + 지문 */
    MEMBER_FINGER(0x72, 0x82, 0x92);

    private int memberType;
    private int authType;
    private int walletType;

    MoaMember(int memberType, int authType, int walletType) {
        this.memberType = memberType;
        this.authType = authType;
        this.walletType = walletType;
    }

    /**
     * 멤버 타입을 리턴한다.</br>
     *
     * <p>비회원, 회원</p>
     */
    public int getMemberType() {
        return memberType;
    }

    /**
     * 인증 타입을 리턴한다.
     *
     * <p>비인증, PIN, 지문</p>
     */
    public int getAuthType() {
        return authType;
    }

    /**
     * 지갑 타입을 리턴한다.
     *
     * <p>복원형</p>
     */
    public int getWalletType() {
        return walletType;
    }
}
