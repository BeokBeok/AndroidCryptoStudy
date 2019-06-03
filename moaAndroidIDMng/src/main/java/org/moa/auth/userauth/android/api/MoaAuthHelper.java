package org.moa.auth.userauth.android.api;

import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;

import org.moa.auth.userauth.manager.AuthToken;
import org.moa.auth.userauth.manager.AutoLogin;
import org.moa.auth.userauth.manager.FingerprintAuth;
import org.moa.auth.userauth.manager.UserControl;

import java.security.PublicKey;
import java.util.Map;
import java.util.StringTokenizer;

public class MoaAuthHelper {
    private Context context;
    private UserControl userControl;
    private AutoLogin autoLogin;

    private MoaAuthHelper(Builder builder) {
        assert builder != null && builder.context != null && builder.uniqueDeviceID != null;

        this.context = builder.context;
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, builder.uniqueDeviceID);
        autoLogin.init(context, builder.uniqueDeviceID);
    }

    public void setNonMemberPIN(String nonMemberId) {
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    public boolean existControlInfo() {
        return userControl.existPreferences();
    }

    public String getMemberInfo(int type) {
        return userControl.getMemberInfo(type);
    }

    public String generatePINRegisterMessage(String id, String password) {
        return MoaCommon.getInstance().generateRegisterMessage(id, password);
    }

    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        return MoaCommon.getInstance().generateLoginRequestMessage(id, password, nonceOTP);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(Map<String, String> fingerprintRegisterData) {
        String curve = fingerprintRegisterData.get("curve");
        String suite = fingerprintRegisterData.get("suite");
        String authTokenData = fingerprintRegisterData.get("authToken");
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        authToken.set(authTokenData);

        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(curve, suite);
        return fingerprintAuth.getRegisterSignature(authTokenData);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(Map<String, String> fingerprintLoginData) {
        String curve = fingerprintLoginData.get("curve");
        String suite = fingerprintLoginData.get("suite");
        String authToken = fingerprintLoginData.get("authToken");
        String nonce = fingerprintLoginData.get("nonce");
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(curve, suite);
        return fingerprintAuth.getLoginSignature(nonce, authToken);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String getAuthTokenData() {
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        return authToken.get();
    }

    public void setControlInfoData(String id, MoaMember moaMember) {
        userControl.setMemberInfo(id, moaMember);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    public String getAutoLoginInfo() {
        String content = autoLogin.getAutoInfo();
        StringTokenizer stringTokenizer = new StringTokenizer(content, "$");
        String type = stringTokenizer.nextToken();
        String info = stringTokenizer.nextToken();
        if (type.equals("0xA1"))
            return info;
        else
            return "";
    }

    public void setAutoLoginInfo(String password) {
        autoLogin.setAutoInfo(password);
    }

    public String getBasePrimaryInfo() {
        return userControl.getBasePrimaryInfo();
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    public void removeAllControlInfo() {
        userControl.removeAllMemberInfo();
    }

    public static class Builder {
        private MoaAuthHelper instance;
        private Context context;
        private String uniqueDeviceID;

        public Builder(Context context) {
            this.context = context;
        }

        public Builder addUniqueDeviceID(String uniqueDeviceID) {
            this.uniqueDeviceID = uniqueDeviceID;
            return this;
        }

        public MoaAuthHelper build() {
            if (instance == null)
                instance = new MoaAuthHelper(this);
            return instance;
        }
    }
}