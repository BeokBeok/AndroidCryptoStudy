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
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

public class MoaAuthHelper {
    private Context context;
    private String uniqueDeviceID;
    private UserControl userControl;
    private AutoLogin autoLogin;

    private MoaAuthHelper() {
    }

    public static MoaAuthHelper getInstance() {
        return Singleton.instance;
    }

    public void init(Context context, String uniqueDeviceID) {
        if (context == null || uniqueDeviceID == null)
            return;
        if (uniqueDeviceID.length() == 0)
            return;
        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    public void setNonMemberPIN(String nonMemberId) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    public boolean existControlInfo() {
        if (isNotValidUniqueDeviceID())
            return false;
        return userControl.existPreferences();
    }

    public String getMemberInfo(int type) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.getMemberInfo(type);
    }

    public String generatePINRegisterMessage(String id, String password) {
        if (isNotValidUniqueDeviceID())
            return "";
        return MoaCommon.getInstance().generateRegisterMessage(id, password);
    }

    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (isNotValidUniqueDeviceID())
            return "";
        return MoaCommon.getInstance().generateLoginRequestMessage(id, password, nonceOTP);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(Map<String, String> fingerprintRegisterData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        String curve = fingerprintRegisterData.get("curve");
        String suite = fingerprintRegisterData.get("suite");
        String authTokenData = fingerprintRegisterData.get("authToken");
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        authToken.setValuesInPreferences("AuthToken.Info", authTokenData);

        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(curve, suite);
        return fingerprintAuth.getRegisterSignature(authTokenData);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(Map<String, String> fingerprintLoginData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
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
        if (isNotValidUniqueDeviceID())
            return "";
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        return authToken.getValuesInPreferences("AuthToken.Info");
    }

    public void setControlInfoData(String id, MoaMember moaMember) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setMemberInfo(id, moaMember);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        if (isNotValidUniqueDeviceID())
            return null;
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    public String getAutoLoginInfo() {
        if (isNotValidUniqueDeviceID())
            return "";
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
        if (isNotValidUniqueDeviceID())
            return;
        autoLogin.setAutoInfo(password);
    }

    public String getBasePrimaryInfo() {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.getBasePrimaryInfo();
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    public void removeAllControlInfo() {
        userControl.removeAllMemberInfo();
    }

    private boolean isNotValidUniqueDeviceID() {
        boolean validUniqueDeviceID = true;
        if (uniqueDeviceID == null)
            validUniqueDeviceID = false;
        else if (uniqueDeviceID.length() == 0)
            validUniqueDeviceID = false;

        if (!validUniqueDeviceID)
            Log.d("MoaLib", "[MoaAuthHelper][isNotValidUniqueDeviceID] Please check whether unique device id valid or not");

        return !validUniqueDeviceID;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final MoaAuthHelper instance = new MoaAuthHelper();
    }
}