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
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

public class MoaAuthHelper implements MoaCommonable {
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

    public void setNonMemberPIN(String nonMemberPIN) {
        if (isNotValidUniqueDeviceID())
            return;
        List<String> nonMemberInfo = Arrays.asList(MoaMember.Type.NONMEMBER.getType(),
                nonMemberPIN, MoaMember.AuthType.INACTIVE.getType(), MoaMember.CoinKeyMgrType.INACTIVE.getType());
        userControl.setMemberInfo(nonMemberInfo);
    }

    public boolean existControlInfo() {
        if (isNotValidUniqueDeviceID())
            return false;
        return userControl.existPreferences();
    }

    public String getMemberInfo(String type) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.getMemberInfo(type);
    }

    public String generatePINRegisterMessage(String id, String password) {
        if (isNotValidUniqueDeviceID())
            return "";
        return generateRegisterMessage(id, password);
    }

    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (isNotValidUniqueDeviceID())
            return "";
        return generateLoginRequestMessage(id, password, nonceOTP);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(List<String> fingerprintRegisterData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        String ECDSA_CURVE = fingerprintRegisterData.get(0);
        String ECDSA_SUITE = fingerprintRegisterData.get(1);
        String AUTH_TOKEN = fingerprintRegisterData.get(2);
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        authToken.setValuesInPreferences(MoaConfigurable.KEY_AUTH_TOKEN, AUTH_TOKEN);

        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuth.getRegisterSignature(AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(List<String> fingerprintLoginData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        String ECDSA_CURVE = fingerprintLoginData.get(0);
        String ECDSA_SUITE = fingerprintLoginData.get(1);
        String AUTH_TOKEN = fingerprintLoginData.get(2);
        String NONCE_OTP = fingerprintLoginData.get(3);
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuth.getLoginSignature(NONCE_OTP, AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String getAuthTokenData() {
        if (isNotValidUniqueDeviceID())
            return "";
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        return authToken.getValuesInPreferences(MoaConfigurable.KEY_AUTH_TOKEN);
    }

    public void setControlInfoData(List<String> data) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setMemberInfo(data);
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
        String content = autoLogin.getValuesInPreferences(MoaConfigurable.KEY_AUTO_LOGIN);
        StringTokenizer stringTokenizer = new StringTokenizer(content, "$");
        String type = stringTokenizer.nextToken();
        String info = stringTokenizer.nextToken();
        if (type.equals(MoaMember.AutoLoginType.ACTIVE.getType()))
            return info;
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
        return userControl.getValuesInPreferences(MoaConfigurable.KEY_BASE_PRIMARY_INDEX);
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setValuesInPreferences(MoaConfigurable.KEY_BASE_PRIMARY_INDEX, userSequenceIndex);
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