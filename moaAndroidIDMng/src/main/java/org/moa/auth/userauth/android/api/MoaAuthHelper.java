package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import org.moa.auth.userauth.manager.AuthToken;
import org.moa.auth.userauth.manager.AutoLogin;
import org.moa.auth.userauth.manager.FingerprintAuth;
import org.moa.auth.userauth.manager.UserControl;

import java.security.PublicKey;
import java.util.Map;

public class MoaAuthHelper {
    private Context context;
    private UserControl userControl;
    private AutoLogin autoLogin;

    private MoaAuthHelper(Builder builder) {
        if (builder == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Builder is null");
            return;
        }
        this.context = builder.context;
    }

    public void setUniqueDeviceID(String uniqueDeviceID) {
        if (uniqueDeviceID == null || uniqueDeviceID.length() < 1) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Unique Device ID not exist");
            return;
        }
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    public void setNonMemberPIN(String nonMemberId) {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return;
        }
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    public boolean existControlInfo() {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return false;
        }
        return userControl.existPreferences();
    }

    public String getMemberInfo(int type) {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return "";
        }
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
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return;
        }
        userControl.setMemberInfo(id, moaMember);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    public String getAutoLoginInfo() {
        if (autoLogin == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Auto Login is null");
            return "";
        }
        return autoLogin.get();
    }

    public void setAutoLoginInfo(String password) {
        if (autoLogin == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "Auto Login is null");
            return;
        }
        autoLogin.set(password);
    }

    public String getBasePrimaryInfo() {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return "";
        }
        return userControl.getBasePrimaryInfo();
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return;
        }
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    public void removeAllControlInfo() {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
            return;
        }
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
            if (instance == null && context != null)
                instance = new MoaAuthHelper(this);
            return instance;
        }
    }
}