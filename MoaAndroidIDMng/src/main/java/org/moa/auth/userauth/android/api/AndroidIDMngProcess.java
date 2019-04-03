package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.manager.AuthToken;
import org.moa.auth.userauth.manager.AutoLogin;
import org.moa.auth.userauth.manager.FingerprintAuth;
import org.moa.auth.userauth.manager.MoaPreferences;
import org.moa.auth.userauth.manager.UserControl;
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
        nonMemberInfo.add(MoaMember.Type.NONMEMBER.getType());
        nonMemberInfo.add(uniqueDeviceID);
        nonMemberInfo.add(MoaMember.AuthType.INACTIVE.getType());
        nonMemberInfo.add(MoaMember.CoinKeyMgrType.INACTIVE.getType());
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
        return userControl.generateRegisterMessage(id, password);
    }

    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (isNotValidUniqueDeviceID())
            return "";
        return userControl.generateLoginRequestMessage(id, password, nonceOTP);
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
        authToken.setValuesInPreferences(MoaPreferences.KEY_AUTH_TOKEN, AUTH_TOKEN);

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
        return authToken.getValuesInPreferences(MoaPreferences.KEY_AUTH_TOKEN);
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

    public void generateWalletInfo(String password) {
        if (isNotValidUniqueDeviceID())
            return;
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        wallet.generateInfo(password);
    }

    public byte[] getSigendTransactionData(String transaction, String password) {
        if (isNotValidUniqueDeviceID())
            return new byte[0];
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        return wallet.generateSignedTransactionData(transaction, password);
    }

    public PublicKey getWalletPublicKey() {
        if (isNotValidUniqueDeviceID())
            return null;
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        return wallet.getPublicKey();
    }

    public boolean verifySignedTransactionData(String plainText, String transactionData) {
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        return wallet.verifySignedData(plainText, Base64.decode(transactionData, Base64.NO_WRAP));
    }

    public boolean existWallet() {
        if (isNotValidUniqueDeviceID())
            return false;
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        return wallet.existPreferences();
    }

    //TODO 지갑 데이터별로 Getter 함수 구현
    public String getWalletContent() {
        if (isNotValidUniqueDeviceID())
            return "";
        Wallet wallet = Wallet.getInstance();
        wallet.init(context);
        String versionInfo = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_VERSION_INFO);
        String osInfo = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_OS_INFO);
        String salt = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_SALT);
        String iterationCount = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_ITERATION_COUNT);
        String cipheredData = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_CIPHERED_DATA);
        String walletPuk = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_PUBLIC_KEY);
        String walletAddr = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_ADDRESS);
        String macData = wallet.getValuesInPreferences(MoaPreferences.KEY_WALLET_MAC_DATA);
        return "Version.Info=" + versionInfo + "\n" +
                "OS.Info=" + osInfo + "\n" +
                "Salt.Value=" + salt + "\n" +
                "Iteration.Count=" + iterationCount + "\n" +
                "Ciphered.Data=" + cipheredData + "\n" +
                "Wallet.PublicKey=" + walletPuk + "\n" +
                "Wallet.Addr=" + walletAddr + "\n" +
                "MAC.Data=" + macData;
    }

    public String getAutoLoginInfo() {
        if (isNotValidUniqueDeviceID())
            return "";
        String content = autoLogin.getValuesInPreferences(MoaPreferences.KEY_AUTO_LOGIN);
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
        return userControl.getValuesInPreferences(MoaPreferences.KEY_BASE_PRIMARY_INDEX);
    }

    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (isNotValidUniqueDeviceID())
            return;
        userControl.setValuesInPreferences(MoaPreferences.KEY_BASE_PRIMARY_INDEX, userSequenceIndex);
    }

    public String getUniqueDeviceInfo() {
        return userControl.getUniqueDeviceInfo();
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