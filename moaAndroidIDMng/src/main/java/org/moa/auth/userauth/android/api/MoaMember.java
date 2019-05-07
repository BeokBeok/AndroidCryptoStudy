package org.moa.auth.userauth.android.api;

public class MoaMember {
    private MoaMember() {}
    
    public enum Get {
        MEMBER("0"),
        MEMBER_ID("1"),
        MEMBER_AUTH("2"),
        MEMBER_COIN_KEY_MGR("3");

        private String type;

        Get(String type) {
            this.type = type;
        }

        public String getType() {
            return type;
        }
    }

    public enum Type {
        INACTIVE("0x70"),
        NONMEMBER("0x71"),
        MEMBER("0x72");

        private String type;

        Type(String type) {
            this.type = type;
        }

        public String getType() {
            return type;
        }
    }

    public enum AuthType {
        INACTIVE("0x80"),
        MEMBER_PIN("0x81"),
        MEMBER_FINGERPRINT("0x82"),
        MEMBER_PIN_FINGERPRINT("0x83");

        private String type;

        AuthType(String type) {
            this.type = type;
        }

        public String getType() {
            return type;
        }
    }

    public enum CoinKeyMgrType {
        INACTIVE("0x90"),
        KEY_GEN_AND_SAVE_APP("0x91"),
        KEY_GEN_AND_SAVE_HSM("0x92"),
        KEY_GEN_HSM_AND_SAVE_HSM_SE("0x93");

        private String type;

        CoinKeyMgrType(String type) {
            this.type = type;
        }

        public String getType() {
            return this.type;
        }
    }

    public enum AutoLoginType {
        INACTIVE("0xA0"),
        ACTIVE("0xA1");

        private String type;

        AutoLoginType(String type) {
            this.type = type;
        }

        public String getType() {
            return this.type;
        }
    }
}
