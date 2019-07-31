package org.moa.auth.userauth.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;

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
 * <p>문제 발생 시, {@literal "MoaLib"} 로그를 참고한다.</p>
 *
 * <p><strong>주의사항</strong></br>
 * getInstance 함수 호출 후 setContext 함수와 setUniqueDeviceID 함수를 호출해야만</br>
 * MoaAuthHelper 인스턴스를 정상적으로 이용이 가능하다.</p>
 *
 * @author 강현석
 */
public class MoaAuthHelper {
    private Context context;
    private UserControl userControl;
    private AutoLogin autoLogin;

    private MoaAuthHelper() {
    }

    /**
     * MoaAuthHelper 객체를 반환한다.
     */
    public static MoaAuthHelper getInstance() {
        return Singleton.instance;
    }

    /**
     * Context를 설정한다.
     *
     * @param context 해당 Activity 의 Context
     */
    public void setContext(@NonNull Context context) {
        this.context = context;
    }

    /**
     * Unique Device ID를 설정하고, 이를 기반으로 UserControl, AutoLogin 클래스를 초기화한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) setContext 함수가 선행 호출된 상태이어야 한다.</br>
     * 2) ({@code uniqueDeviceID.length() < 1}) 이면 안된다.</p>
     *
     * @param uniqueDeviceID unique device ID 값
     */
    public void setUniqueDeviceID(@NonNull String uniqueDeviceID) {
        if (uniqueDeviceID.length() < 1) {
            Log.d("MoaLib", "uniqueDeviceID not validate");
            return;
        }
        if (context == null) {
            Log.d("MoaLib", "context is null");
            return;
        }
        userControl = UserControl.getInstance();
        autoLogin = AutoLogin.getInstance();
        userControl.init(context, uniqueDeviceID);
        autoLogin.init(context, uniqueDeviceID);
    }

    /**
     * 비회원 정보를 설정한다.
     *
     * @param nonMemberId 비회원 ID
     */
    public void setNonMemberPIN(@NonNull String nonMemberId) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return;
        }
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    /**
     * 현재 Member ID 를 얻어온다.
     *
     */
    public String getCurrentMemberID() {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.getMemberInfo(1);
    }

    /**
     * PIN 회원가입 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * @param id       회원 ID
     * @param password 패스워드
     */
    public String generatePINRegisterMessage(
            @NonNull String id,
            @NonNull String password
    ) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.generateRegisterMessage(id, password);
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
     */
    public String generatePINLoginRequestMessage(
            @NonNull String id,
            @NonNull String password,
            @NonNull String nonceOTP
    ) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.generateLoginRequestMessage(id, password, nonceOTP);
    }

    /**
     * PIN 초기화 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * @param id      회원 ID
     * @param resetPw 초기화 할 패스워드
     */
    public String generatePINResetRequestMessage(
            @NonNull String id,
            @NonNull String resetPw
    ) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.generatePINResetRequestMessage(id, resetPw);
    }

    /**
     * PIN 변경 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * @param id        회원 ID
     * @param currentPw 현재 패스워드
     * @param newPw     새 패스워드
     */
    public String generatePINChangeRequestMessage(
            @NonNull String id,
            @NonNull String currentPw,
            @NonNull String newPw
    ) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.generatePINChangeRequestMessage(id, currentPw, newPw);
    }

    /**
     * 지문 등록 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) ({@code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</br>
     * 2) ({@code fingerprintRegisterData.size != 3}) 이면 안된다.</br>
     *
     * @param fingerprintRegisterData curve, suite, authToken 데이터</br>
     *                                HashMap 으로 키 별(curve, suite, authToken) 데이터 설정 및 전달</br>
     *                                Example:</br>
     *                                <pre>{@code Map<String, String> fingerprintRegisterData = new HashMap<>();}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("curve", "secp256r1");}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("suite", "SHA256withECDSA");}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("authToken", base64AuthToken);}}</pre>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(@NonNull Map<String, String> fingerprintRegisterData) {
        if (fingerprintRegisterData.size() != 3) {
            Log.d("MoaLib", "fingerprintRegisterData not validate");
            return new byte[0];
        }
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
     * <p><strong>주의사항</strong></br>
     * 1) ({@code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</br>
     * 2) ({@code fingerprintLoginData.size != 4}) 이면 안된다.</br>
     *
     * @param fingerprintLoginData curve, suite, authToken, nonce 데이터</br>
     *                             HashMap 으로 키 별(curve, suite, authToken, nonce) 데이터 설정 및 전달</br>
     *                             Example:</br>
     *                             <pre>{@code Map<String, String> fingerprintRegisterData = new HashMap<>();}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("curve", "secp256r1");}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("suite", "SHA256withECDSA");}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("authToken", base64AuthToken);}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("nonce", nonceOTP);}}</pre>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(@NonNull Map<String, String> fingerprintLoginData) {
        if (fingerprintLoginData.size() != 4) {
            Log.d("MoaLib", "fingerprintLoginData not validate");
            return new byte[0];
        }
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
     * <p><strong>주의사항</strong></br>
     * ({@code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</p>
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
     * <p>주로 서명 검증 시 필요하다.</p>
     * <p><strong>주의사항</strong></br>
     * ({@code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</p>
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
     * @param moaMember MoaMember 열거타입</br>
     *                  Example:</br>
     *                  NON_MEMBER: 비회원</br>
     *                  MEMBER_PIN: 회원&PIN</br>
     *                  MEMBER_FINGER: 회원&지문</br>
     */
    public void setControlInfoData(
            @NonNull String id,
            @NonNull MoaMember moaMember
    ) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return;
        }
        userControl.setMemberInfo(id, moaMember);
    }

    /**
     * 자동 로그인 정보를 리턴한다.
     *
     */
    public String getAutoLoginInfo() {
        if (autoLogin == null) {
            Log.d("MoaLib", "autoLogin is null");
            return "";
        }
        return autoLogin.get();
    }

    /**
     * 자동 로그인 정보를 저장한다.
     *
     * @param password 자동 로그인 시 필요한 패스워드</br>
     *                 null 전달 시, 자동 로그인 비활성화
     */
    public void setAutoLoginInfo(String password) {
        if (autoLogin == null) {
            Log.d("MoaLib", "autoLogin is null");
            return;
        }
        autoLogin.set(password);
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 리턴한다.
     *
     */
    public String getBasePrimaryInfo() {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.getBasePrimaryInfo();
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 저장한다.
     *
     * @param userSequenceIndex Base Primary Info 값
     */
    public void setBasePrimaryInfo(@NonNull String userSequenceIndex) {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return;
        }
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    /**
     * 모든 Control Info 정보를 제거한다.
     *
     */
    public void removeControlInfo() {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return;
        }
        userControl.removeControlInfo();
    }

    /**
     * 회원 ID 정보를 조회한다.
     *
     */
    public String getMemberID() {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.getMemberID();
    }

    /**
     * 비회원 ID 정보를 조회한다.
     *
     */
    public String getNonMemberID() {
        if (userControl == null) {
            Log.d("MoaLib", "userControl is null");
            return "";
        }
        return userControl.getNonMemberID();
    }

    /**
     * 싱글턴 인스턴스 생성을 도와준다.
     *
     * <p>MoaAuthHelper 인스턴스를 한 번만 생성한다.</br>
     * 이너클래스에서 인스턴스를 생성하므로, 스레드에 안전하다.</p>
     *
     * @author 강현석
     */
    public static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static MoaAuthHelper instance = new MoaAuthHelper();
    }
}