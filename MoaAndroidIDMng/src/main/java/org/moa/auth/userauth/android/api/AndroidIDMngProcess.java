package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

public class AndroidIDMngProcess {
    private Context context;
    private String uniqueDeviceID;
    private ControlInfoManager controlInfoManager;
    private AutoLoginManager autoLoginManager;

    private AndroidIDMngProcess() {
    }

    public static AndroidIDMngProcess getInstance() {
        return Singleton.instance;
    }

    public void init(Context context, String uniqueDeviceID) {
        if (context == null || uniqueDeviceID == null)
            return;
        if (uniqueDeviceID.length() == 0)
            return;
        this.context = context;
        this.uniqueDeviceID = uniqueDeviceID;
        controlInfoManager = ControlInfoManager.getInstance();
        autoLoginManager = AutoLoginManager.getInstance();
        controlInfoManager.init(context, uniqueDeviceID);
    }

    public void generateNonMemberPIN() {
        if (isNotValidUniqueDeviceID())
            return;
        List<String> nonMemberInfo = new ArrayList<>();
        nonMemberInfo.add(MemberInfo.Type.NONMEMBER.getType());
        nonMemberInfo.add(uniqueDeviceID);
        nonMemberInfo.add(MemberInfo.AuthType.INACTIVE.getType());
        nonMemberInfo.add(MemberInfo.CoinKeyMgrType.INACTIVE.getType());
        controlInfoManager.setMemberInfo(nonMemberInfo);
    }

    public boolean existControlInfo() {
        if (isNotValidUniqueDeviceID())
            return false;
        return controlInfoManager.existPreference();
    }

    public String getMemberInfo(String type) {
        if (isNotValidUniqueDeviceID())
            return "";
        return controlInfoManager.getMemberInfo(type);
    }

    public String idPswRegistMsgGenProcessForAndroid(String id, String password) {
        if (isNotValidUniqueDeviceID())
            return "";
        return controlInfoManager.generateOrGetRegisterMessage(id, password);
    }

    public String pinLoginRequestMsgGenProcessForAndroid(String id, String password, String nonceOTP) {
        if (isNotValidUniqueDeviceID())
            return "";
        return controlInfoManager.generateOrGetLoginRequestMessage(id, password, nonceOTP);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(List<String> fingerprintRegisterData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        final String ECDSA_CURVE = fingerprintRegisterData.get(0);
        final String ECDSA_SUITE = fingerprintRegisterData.get(1);
        final String AUTH_TOKEN = fingerprintRegisterData.get(2);
        AuthTokenManager authTokenManager = AuthTokenManager.getInstance();
        authTokenManager.init(context);
        authTokenManager.setValuesInPreference(SharedPreferencesManager.KEY_AUTH_TOKEN, AUTH_TOKEN);

        FingerprintAuthManger fingerprintAuthManger = FingerprintAuthManger.getInstance();
        fingerprintAuthManger.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuthManger.getRegisterSignature(AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(List<String> fingerprintLoginData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        final String ECDSA_CURVE = fingerprintLoginData.get(0);
        final String ECDSA_SUITE = fingerprintLoginData.get(1);
        final String AUTH_TOKEN = fingerprintLoginData.get(2);
        final String NONCE_OTP = fingerprintLoginData.get(3);
        FingerprintAuthManger fingerprintAuthManger = FingerprintAuthManger.getInstance();
        fingerprintAuthManger.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuthManger.getLoginSignature(NONCE_OTP, AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String getAuthTokenData() {
        if (isNotValidUniqueDeviceID())
            return "";
        AuthTokenManager authTokenManager = AuthTokenManager.getInstance();
        authTokenManager.init(context);
        return authTokenManager.getValuesInPreference(SharedPreferencesManager.KEY_AUTH_TOKEN);
    }

    public void setControlInfoData(List<String> data) {
        if (isNotValidUniqueDeviceID())
            return;
        controlInfoManager.setMemberInfo(data);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        if (isNotValidUniqueDeviceID())
            return null;
        FingerprintAuthManger fingerprintAuthManger = FingerprintAuthManger.getInstance();
        return fingerprintAuthManger.getPublicKey();
    }

    public void generateWalletInfo(String password) {
        if (isNotValidUniqueDeviceID())
            return;
        WalletManager walletManager = WalletManager.getInstance();
        walletManager.init(context);
        List<String> requiredWalletData = walletManager.generateRequiredData(password);
        walletManager.createFile(requiredWalletData);
    }

    public byte[] getSigendTransactionData(String transaction, String password) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        WalletManager walletManager = WalletManager.getInstance();
        walletManager.init(context);
        return walletManager.generateSignedTransactionData(transaction, password);
    }

    public PublicKey getWalletPublicKey() {
        if (isNotValidUniqueDeviceID())
            return null;
        WalletManager walletManager = WalletManager.getInstance();
        walletManager.init(context);
        return walletManager.getPublicKey();
    }

    public boolean existWalletFile() {
        if (isNotValidUniqueDeviceID())
            return false;
        WalletManager walletManager = WalletManager.getInstance();
        walletManager.init(context);
        return walletManager.existFile();
    }

    public String getWalletContent() {
        if (isNotValidUniqueDeviceID())
            return "";
        WalletManager walletManager = WalletManager.getInstance();
        walletManager.init(context);
        return walletManager.getContent();
    }

    public void setAutoLogin(String password) {
        if (isNotValidUniqueDeviceID())
            return;
        autoLoginManager.setAutoInfo(password);
    }

    public String getAutoLoginInfo() {
        if (isNotValidUniqueDeviceID())
            return "";
        String content = autoLoginManager.getValuesInPreference(SharedPreferencesManager.KEY_AUTO_LOGIN);
        StringTokenizer stringTokenizer = new StringTokenizer(content, "$");
        final String type = stringTokenizer.nextToken();
        final String info = stringTokenizer.nextToken();
        if (type.equals(MemberInfo.AutoLoginType.ACTIVE.getType()))
            return info;
        return "";
    }

    private boolean isNotValidUniqueDeviceID() {
        boolean validUniqueDeviceID = true;
        if (uniqueDeviceID == null)
            validUniqueDeviceID = false;
        else if (uniqueDeviceID.length() == 0)
            validUniqueDeviceID = false;

        if (!validUniqueDeviceID)
            Log.d("MoaLib", "[AndroidIDMngProcess][isNotValidUniqueDeviceID] Please check whether unique device id valid or not");

        return !validUniqueDeviceID;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final AndroidIDMngProcess instance = new AndroidIDMngProcess();
    }
}