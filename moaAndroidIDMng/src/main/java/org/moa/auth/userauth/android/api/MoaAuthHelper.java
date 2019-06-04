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

/**
 * 회원 관련 인증 절차를 도와준다.
 *
 * <p>PIN, 지문을 이용한 회원 가입 및 로그인을 지원한다.</p>
 *
 * @author 강현석
 */
public class MoaAuthHelper {
    private Context context;
    private UserControl userControl;
    private AutoLogin autoLogin;

    private MoaAuthHelper(Builder builder) {
        if (builder == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Builder is null");
        this.context = builder.context;
    }

    /**
     * Unique Device ID를 설정하고, 이를 기반으로 UserControl, AutoLogin 클래스를 초기화한다.
     *
     * @param uniqueDeviceID unique device ID 값; null 이거나 length 가 0이면 안된다.
     * @throws RuntimeException ({@code uniqueDeviceID == null || uniqueDeviceID.length() < 1}) 이면 발생한다.
     */
    public void setUniqueDeviceID(String uniqueDeviceID) {
        if (uniqueDeviceID == null || uniqueDeviceID.length() < 1)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Unique Device ID not exist");
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    /**
     * 비회원 정보를 설정한다.
     *
     * @param nonMemberId 비회원 ID; 비회원 ID가 null 이면 안된다.
     * @throws RuntimeException 비회원 ID가 null 이 아니거나, setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public void setNonMemberPIN(String nonMemberId) {
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    /**
     * Member 정보(Member 타입 / ID / 인증 방식 / 지갑 타입)를 얻어온다.
     *
     * @param type 타입</br>
     *             0: 비회원/회원 여부, 1: 비회원/회원 ID, 2: 인증 방식(PIN 또는 지문), 3: 복원형 지갑 타입
     * @throws RuntimeException type 의 범위가 0 - 3 사이여야 하며, setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public String getMemberInfo(int type) {
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        return userControl.getMemberInfo(type);
    }

    /**
     * PIN 회원가입 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * @param id       회원 ID
     * @param password 패스워드
     * @throws RuntimeException id 나 password 가 null 이 아니여야 한다.</br>
     *                          (@{code id == null || password == null}) 이면 발생한다.
     */
    public String generatePINRegisterMessage(String id, String password) {
        if (id == null || password == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Id or password is null");
        return MoaCommon.getInstance().generateRegisterMessage(id, password);
    }

    /**
     * PIN 로그인 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * @param id       회원 ID
     * @param password 패스워드
     * @param nonceOTP 서버에서 전달받은 nonce 값
     * @throws RuntimeException id 나 password 나 nonceOTP 가 null 이 아니여야 한다.</br>
     *                          (@{code id == null || password == null || nonceOTP == null}) 이면 발생한다.
     */
    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (id == null || password == null || nonceOTP == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Id or password or nonceOTP is null");
        return MoaCommon.getInstance().generateLoginRequestMessage(id, password, nonceOTP);
    }

    /**
     * 지문 등록 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>API Level 23 이상부터 사용 가능하다.</p>
     *
     * @param fingerprintRegisterData curve, suite, authToken 데이터</br>
     *                                WeakHashMap 으로 키 별(curve, suite, authToken) 데이터 설정 및 전달</br>
     *                                Example:</br>
     *                                {@code Map<String, String> fingerprintRegisterData = new WeakHashMap<>();
     *                                fingerprintRegisterData.put("curve", "secp256r1");
     *                                fingerprintRegisterData.put("suite", "SHA256withECDSA");
     *                                fingerprintRegisterData.put("authToken", base64AuthToken);}
     * @throws RuntimeException fingerprintRegisterData 가 null 이 아니여야 한다.
     *                          (@{code fingerprintRegisterData == null}) 이면 발생한다.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(Map<String, String> fingerprintRegisterData) {
        if (fingerprintRegisterData == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "FingerprintRegisterData is null");
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

    /**
     * 지문 로그인 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>API Level 23 부터 사용 가능하다.</p>
     *
     * @param fingerprintLoginData curve, suite, authToken, nonce 데이터</br>
     *                             WeakHashMap 으로 키 별(curve, suite, authToken, nonce) 데이터 설정 및 전달</br>
     *                             Example:</br>
     *                             {@code Map<String, String> fingerprintRegisterData = new WeakHashMap<>();
     *                             fingerprintRegisterData.put("curve", "secp256r1");
     *                             fingerprintRegisterData.put("suite", "SHA256withECDSA");
     *                             fingerprintRegisterData.put("authToken", base64AuthToken);
     *                             fingerprintRegisterData.put("nonce", nonceOTP);}
     * @throws RuntimeException fingerprintLoginData 가 null 이 아니여야 한다.
     *                          (@{code fingerprintLoginData == null}) 이면 발생한다.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(Map<String, String> fingerprintLoginData) {
        if (fingerprintLoginData == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "FingerprintLoginData is null");
        String curve = fingerprintLoginData.get("curve");
        String suite = fingerprintLoginData.get("suite");
        String authToken = fingerprintLoginData.get("authToken");
        String nonce = fingerprintLoginData.get("nonce");
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        fingerprintAuth.init(curve, suite);
        return fingerprintAuth.getLoginSignature(nonce, authToken);
    }

    /**
     * 인증 토큰 값을 리턴한다.
     *
     * <p>API Level 23 부터 사용 가능하다.</p>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public String getAuthTokenData() {
        AuthToken authToken = AuthToken.getInstance();
        authToken.init(context);
        return authToken.get();
    }

    /**
     * 지문 등록 시 생성된 공개키를 리턴한다.
     *
     * <p>API Level 23 부터 사용 가능하다.</p>
     * <p>주로 서명 검증 시 필요하다.</p>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    /**
     * Control Info 에 Member 정보를 저장한다.
     *
     * @param id        회원 ID; null 이면 안된다.
     * @param moaMember MoaMember 열거타입; null 이면 안된다.</br>
     *                  Example:</br>
     *                  NON_MEMBER: 비회원
     *                  MEMBER_PIN: 회원&PIN
     *                  MEMBER_FINGER: 회원&지문
     * @throws RuntimeException 회원 ID와 MoaMember 가 null 이 아니면서, setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public void setControlInfoData(String id, MoaMember moaMember) {
        if (id == null || moaMember == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Id or moaMember is null");
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        userControl.setMemberInfo(id, moaMember);
    }

    /**
     * 자동 로그인 정보를 리턴한다.
     *
     * @throws RuntimeException setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public String getAutoLoginInfo() {
        if (autoLogin == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Auto Login is null");
        return autoLogin.get();
    }

    /**
     * 자동 로그인 정보를 저장한다.
     *
     * @param password 자동 로그인 시 필요한 패스워드</br>
     *                 null 전달 시, 자동 로그인 비활성화
     * @throws RuntimeException setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public void setAutoLoginInfo(String password) {
        if (autoLogin == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Auto Login is null");
        autoLogin.set(password);
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 리턴한다.
     *
     * @throws RuntimeException setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public String getBasePrimaryInfo() {
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        return userControl.getBasePrimaryInfo();
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 저장한다.
     *
     * @param userSequenceIndex Base Primary Info 값; null 이면 안된다.
     * @throws RuntimeException userSequenceIndex 가 null 이 아니면서, setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (userSequenceIndex == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "UserSequenceIndex is null");
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    /**
     * 모든 Control Info 정보를 제거한다.
     *
     * @throws RuntimeException setUniqueDeviceID 함수가 이미 호출된 상태이어야 하며,</br>
     *                          (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 경우 발생한다.
     */
    public void removeAllControlInfo() {
        if (userControl == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "User Control is null");
        userControl.removeAllMemberInfo();
    }

    /**
     * 빌더를 통하여 인스턴스 생성을 도와준다.
     *
     * <p>Inner class 를 활용하여 인스턴스를 생성하므로 스레드에 안전하다.</p>
     * <p>
     * Example:</br>
     * {@code new MoaAuthHelper.Builder(this).build()}
     *
     * @author 강현석
     */
    public static class Builder {
        @SuppressLint("StaticFieldLeak")
        private static MoaAuthHelper instance;
        private Context context;

        /**
         * 빌더 사용을 위한 생성자
         *
         * @param context shared preference 를 사용하기 위한 context
         */
        public Builder(Context context) {
            this.context = context;
        }

        /**
         * MoaAuthHelper 인스턴스를 생성한다.
         *
         * @return 생성된 MoaWalletHelper 인스턴스
         */
        public MoaAuthHelper build() {
            return new MoaAuthHelper(this);
        }
    }
}