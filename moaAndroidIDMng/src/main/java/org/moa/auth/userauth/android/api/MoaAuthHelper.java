package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
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
        assert builder != null && builder.context != null;
        this.context = builder.context;
    }

    public void setUniqueDeviceID(String uniqueDeviceID) {
        if (uniqueDeviceID == null || uniqueDeviceID.length() < 1)
            throw new RuntimeException("Unique Device ID not exist");
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    public void setNonMemberPIN(String nonMemberId) {
        if (userControl != null)
            userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    public boolean existControlInfo() {
        if (userControl != null)
            return userControl.existPreferences();
        else
            return false;
    }

    public String getMemberInfo(int type) {
        if (userControl != null)
            return userControl.getMemberInfo(type);
        else
            return "";
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
        if (userControl == null)
            throw new RuntimeException("User Control is null");
        userControl.setMemberInfo(id, moaMember);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    public String getAutoLoginInfo() {
        if (autoLogin != null)
            return autoLogin.get();
        else
            return "";
    }

    public void setAutoLoginInfo(String password) {
        if (autoLogin == null)
            throw new RuntimeException("Auto Login is null");
        autoLogin.set(password);
    }

    public String getBasePrimaryInfo() {
        if (userControl != null)
            return userControl.getBasePrimaryInfo();
        else
            return "";
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (userControl == null)
            throw new RuntimeException("User Control is null");
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    public void removeAllControlInfo() {
        if (userControl == null)
            throw new RuntimeException("User Control is null");
        userControl.removeAllMemberInfo();
    }

    public static class Builder {
        @SuppressLint("StaticFieldLeak")
        private static MoaAuthHelper instance;
        private Context context;

        public Builder(Context context) {
            this.context = context;
        }

        public MoaAuthHelper build() {
            if (instance == null)
                instance = new MoaAuthHelper(this);
            return instance;
        }
    }
}