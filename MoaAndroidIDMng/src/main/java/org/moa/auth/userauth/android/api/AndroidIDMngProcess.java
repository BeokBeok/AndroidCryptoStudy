package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import org.moa.auth.userauth.manager.AuthToken;
import org.moa.auth.userauth.manager.AutoLogin;
import org.moa.auth.userauth.manager.UserControl;
import org.moa.auth.userauth.manager.FingerprintAuthentication;
import org.moa.auth.userauth.manager.SharedPreferencesImpl;
import org.moa.auth.userauth.manager.BasePrimary;
import org.moa.auth.userauth.manager.Wallet;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

public class AndroidIDMngProcess {
    private Context context;
    private String uniqueDeviceID;
    private UserControl userControl;
    private AutoLogin autoLogin;

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
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    public void setNonMemberPIN() {
        if (isNotValidUniqueDeviceID())
            return;
        List<String> nonMemberInfo = new ArrayList<>();
        nonMemberInfo.add(Member.Type.NONMEMBER.getType());
        nonMemberInfo.add(uniqueDeviceID);
        nonMemberInfo.add(Member.AuthType.INACTIVE.getType());
        nonMemberInfo.add(Member.CoinKeyMgrType.INACTIVE.getType());
        userControl.setMemberInfo(nonMemberInfo);
    }

    public boolean existControlInfo() {
        if (isNotValidUniqueDeviceID())
            return false;
        return userControl.existPreference();
    }

    public String getMemberInfo(String type) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.getMemberInfo(type);
    }

    public String generatePINRegisterMessage(String id, String password) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.generateOrGetRegisterMessage(id, password);
    }

    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.generateOrGetLoginRequestMessage(id, password, nonceOTP);
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
        authToken.setValuesInPreference(SharedPreferencesImpl.KEY_AUTH_TOKEN, AUTH_TOKEN);

        FingerprintAuthentication fingerprintAuthentication = FingerprintAuthentication.getInstance();
        fingerprintAuthentication.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuthentication.getRegisterSignature(AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(List<String> fingerprintLoginData) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        String ECDSA_CURVE = fingerprintLoginData.get(0);
        String ECDSA_SUITE = fingerprintLoginData.get(1);
        String AUTH_TOKEN = fingerprintLoginData.get(2);
        String NONCE_OTP = fingerprintLoginData.get(3);
        FingerprintAuthentication fingerprintAuthentication = FingerprintAuthentication.getInstance();
        fingerprintAuthentication.init(ECDSA_CURVE, ECDSA_SUITE);
        return fingerprintAuthentication.getLoginSignature(NONCE_OTP, AUTH_TOKEN);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String getAuthTokenData() {
        if (isNotValidUniqueDeviceID())
            return "";
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        return authToken.getValuesInPreference(SharedPreferencesImpl.KEY_AUTH_TOKEN);
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
        FingerprintAuthentication fingerprintAuthentication = FingerprintAuthentication.getInstance();
        return fingerprintAuthentication.getPublicKey();
    }

    public void generateWalletInfo(String password) {
        if (isNotValidUniqueDeviceID())
            return;
        Wallet walletManager = Wallet.getInstance();
        walletManager.init(context);
        walletManager.generateInfo(password);
    }

    public byte[] getSigendTransactionData(String transaction, String password) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        Wallet walletManager = Wallet.getInstance();
        walletManager.init(context);
        return walletManager.generateSignedTransactionData(transaction, password);
    }

    public PublicKey getWalletPublicKey() {
        if (isNotValidUniqueDeviceID())
            return null;
        Wallet walletManager = Wallet.getInstance();
        walletManager.init(context);
        return walletManager.getPublicKey();
    }

    public boolean existWallet() {
        if (isNotValidUniqueDeviceID())
            return false;
        Wallet walletManager = Wallet.getInstance();
        walletManager.init(context);
        return walletManager.existPreference();
    }

    //TODO 지갑 데이터별로 Getter 함수 구현
    public String getWalletContent() {
        if (isNotValidUniqueDeviceID())
            return "";
        Wallet walletManager = Wallet.getInstance();
        walletManager.init(context);
        String versionInfo = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_VERSION_INFO);
        String osInfo = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_OS_INFO);
        String salt = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_SALT);
        String iterationCount = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_ITERATION_COUNT);
        String cipheredData = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_CIPHERED_DATA);
        String walletPuk = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_PUBLIC_KEY);
        String walletAddr = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_ADDRESS);
        String macData = walletManager.getValuesInPreference(SharedPreferencesImpl.KEY_WALLET_MAC_DATA);
        String walletInfo = "Version.Info=" + versionInfo + "\n" +
                "OS.Info=" + osInfo + "\n" +
                "Salt.Value=" + salt + "\n" +
                "Iteration.Count=" + iterationCount + "\n" +
                "Ciphered.Data=" + cipheredData + "\n" +
                "Wallet.PublicKey=" + walletPuk + "\n" +
                "Wallet.Addr=" + walletAddr + "\n" +
                "MAC.Data=" + macData;
        return walletInfo;
    }

    public void setAutoLoginInfo(String password) {
        if (isNotValidUniqueDeviceID())
            return;
        autoLogin.setAutoInfo(password);
    }

    public String getAutoLoginInfo() {
        if (isNotValidUniqueDeviceID())
            return "";
        String content = autoLogin.getValuesInPreference(SharedPreferencesImpl.KEY_AUTO_LOGIN);
        StringTokenizer stringTokenizer = new StringTokenizer(content, "$");
        String type = stringTokenizer.nextToken();
        String info = stringTokenizer.nextToken();
        if (type.equals(Member.AutoLoginType.ACTIVE.getType()))
            return info;
        return "";
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        BasePrimary basePrimary = BasePrimary.getInstance();
        basePrimary.init(context, uniqueDeviceID);
        basePrimary.setBasePrimaryInfo(userSequenceIndex);
    }

    public String getBasePrimaryInfo() {
        BasePrimary basePrimary = BasePrimary.getInstance();
        basePrimary.init(context, uniqueDeviceID);
        return basePrimary.getBasePrimaryInfo();
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