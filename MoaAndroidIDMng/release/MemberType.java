package org.moa.auth.userauth.android.api;

public enum MemberType {
    NONMEMBER("0x71"),
    MEMBER("0x72");

    private String type;

    MemberType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
