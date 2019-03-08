package org.moa.auth.userauth.android.api;

public enum MemberAuthType {
    MEMBER_PIN("0x81"),
    MEMBER_FINGERPRINT("0x82"),
    MEMBER_PIN_FINGERPRINT("0x83");

    private String type;

    MemberAuthType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
