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
    public void setContext(Context context) {
        this.context = context;
    }

    /**
     * Unique Device ID를 설정하고, 이를 기반으로 UserControl, AutoLogin 클래스를 초기화한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) setContext 함수가 선행 호출된 상태이어야 한다.</br>
     * 2) ({@code uniqueDeviceID == null || uniqueDeviceID.length() < 1}) 이면 안된다.</p>
     *
     * @param uniqueDeviceID unique device ID 값
     */
    public void setUniqueDeviceID(String uniqueDeviceID) {
        if (uniqueDeviceID == null || uniqueDeviceID.length() < 1) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "uniqueDeviceID is : " + uniqueDeviceID);
            return;
        }
        if (context == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "context is null");
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
     * <p><strong>주의사항</strong></br>
     * 1) 비회원 ID가 null 이면 안된다.</br>
     * 2) (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     *
     * @param nonMemberId 비회원 ID
     */
    public void setNonMemberPIN(String nonMemberId) {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return;
        }
        userControl.setMemberInfo(nonMemberId, MoaMember.NON_MEMBER);
    }

    /**
     * Member 정보(Member 타입 / ID / 인증 방식 / 지갑 타입)를 얻어온다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) type 이 유효 범위 {@literal (0 ~ 3)} 이어야 한다.</br>
     * 2) (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     *
     * @param type 타입</br>
     *             0: 비회원/회원 여부, 1: 비회원/회원 ID, 2: 인증 방식(PIN 또는 지문), 3: 복원형 지갑 타입
     */
    public String getMemberInfo(int type) {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return "";
        }
        return userControl.getMemberInfo(type);
    }

    /**
     * PIN 회원가입 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * <p><strong>주의사항</strong></br>
     * (@{code id == null || password == null}) 이면 안된다.</p>
     *
     * @param id       회원 ID
     * @param password 패스워드
     */
    public String generatePINRegisterMessage(String id, String password) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return "";
        }
        if (password == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "password is null");
            return "";
        }
        return MoaCommon.getInstance().generateRegisterMessage(id, password);
    }

    /**
     * PIN 로그인 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * <p><strong>주의사항</strong></br>
     * (@{code id == null || password == null || nonceOTP == null}) 이면 안된다.</p>
     *
     * @param id       회원 ID
     * @param password 패스워드
     * @param nonceOTP 서버에서 전달받은 nonce 값
     */
    public String generatePINLoginRequestMessage(String id, String password, String nonceOTP) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return "";
        }
        if (password == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "password is null");
            return "";
        }
        if (nonceOTP == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "nonceOTP is null");
            return "";
        }
        return MoaCommon.getInstance().generateLoginRequestMessage(id, password, nonceOTP);
    }

    /**
     * PIN 초기화 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * <p><strong>주의사항</strong></br>
     * (@{code id == null || resetPw == null}) 이면 안된다.</p>
     *
     * @param id      회원 ID
     * @param resetPw 초기화 할 패스워드
     */
    public String generatePINResetRequestMessage(String id, String resetPw) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return "";
        }
        if (resetPw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "resetPw is null");
            return "";
        }
        return MoaCommon.getInstance().generatePINResetRequestMessage(id, resetPw);
    }

    /**
     * PIN 변경 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p>Pie(9) 버전부터 Bouncy Castle Provider 미지원으로 인하여,</br>
     * Bouncy Castle Provider 를 제거하여 동작하도록 구현했다.</p>
     *
     * <p><strong>주의사항</strong></br>
     * (@{code id == null || resetPw == null}) 이면 안된다.</p>
     *
     * @param id        회원 ID
     * @param currentPw 현재 패스워드
     * @param newPw     새 패스워드
     */
    public String generatePINChangeRequestMessage(String id, String currentPw, String newPw) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return "";
        }
        if (currentPw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "currentPw is null");
            return "";
        }
        if (newPw == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "newPw is null");
            return "";
        }
        return MoaCommon.getInstance().generatePINChangeRequestMessage(id, currentPw, newPw);
    }

    /**
     * 지문 등록 시 서버에 요청하는 메시지를 생성하여 리턴한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) (@{code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</br>
     * 2) (@{code fingerprintRegisterData == null || fingerprintRegisterData.size != 3}) 이면 안된다.</br>
     *
     * @param fingerprintRegisterData curve, suite, authToken 데이터</br>
     *                                WeakHashMap 으로 키 별(curve, suite, authToken) 데이터 설정 및 전달</br>
     *                                Example:</br>
     *                                <pre>{@code Map<String, String> fingerprintRegisterData = new WeakHashMap<>();}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("curve", "secp256r1");}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("suite", "SHA256withECDSA");}</pre>
     *                                <pre>{@code fingerprintRegisterData.put("authToken", base64AuthToken);}}</pre>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintRegisterECDSASign(Map<String, String> fingerprintRegisterData) {
        if (fingerprintRegisterData == null || fingerprintRegisterData.size() != 3) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "fingerprintRegisterData not validate");
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
     * 1) (@{code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</br>
     * 2) (@{code fingerprintLoginData == null || fingerprintLoginData.size != 4}) 이면 안된다.</br>
     *
     * @param fingerprintLoginData curve, suite, authToken, nonce 데이터</br>
     *                             WeakHashMap 으로 키 별(curve, suite, authToken, nonce) 데이터 설정 및 전달</br>
     *                             Example:</br>
     *                             <pre>{@code Map<String, String> fingerprintRegisterData = new WeakHashMap<>();}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("curve", "secp256r1");}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("suite", "SHA256withECDSA");}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("authToken", base64AuthToken);}</pre>
     *                             <pre>{@code fingerprintRegisterData.put("nonce", nonceOTP);}}</pre>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public byte[] getFingerprintLoginECDSASign(Map<String, String> fingerprintLoginData) {
        if (fingerprintLoginData == null || fingerprintLoginData.size() != 4) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "fingerprintLoginData not validate");
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
     * (@{code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</p>
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
     * (@{code Build.VERSION.SDK_INT >= Build.VERSION_CODES.M}) 이어야 한다.</p>
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public PublicKey getFingerprintPublicKey() {
        FingerprintAuth fingerprintAuth = FingerprintAuth.getInstance();
        return fingerprintAuth.getPublicKey();
    }

    /**
     * Control Info 에 Member 정보를 저장한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) ({@code id == null || moaMember == null}) 이면 안된다.</br>
     * 2) (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     *
     * @param id        회원 ID; null 이면 안된다.
     * @param moaMember MoaMember 열거타입</br>
     *                  Example:</br>
     *                  NON_MEMBER: 비회원</br>
     *                  MEMBER_PIN: 회원&PIN</br>
     *                  MEMBER_FINGER: 회원&지문</br>
     */
    public void setControlInfoData(String id, MoaMember moaMember) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return;
        }
        if (moaMember == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "moaMember is null");
            return;
        }
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return;
        }
        userControl.setMemberInfo(id, moaMember);
    }

    /**
     * 자동 로그인 정보를 리턴한다.
     *
     * <p><strong>주의사항</strong></br>
     * (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     */
    public String getAutoLoginInfo() {
        if (autoLogin == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "autoLogin is null");
            return "";
        }
        return autoLogin.get();
    }

    /**
     * 자동 로그인 정보를 저장한다.
     *
     * <p><strong>주의사항</strong></br>
     * (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     *
     * @param password 자동 로그인 시 필요한 패스워드</br>
     *                 null 전달 시, 자동 로그인 비활성화
     */
    public void setAutoLoginInfo(String password) {
        if (autoLogin == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "autoLogin is null");
            return;
        }
        autoLogin.set(password);
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 리턴한다.
     *
     * <p><strong>주의사항</strong></br>
     * (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     */
    public String getBasePrimaryInfo() {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return "";
        }
        return userControl.getBasePrimaryInfo();
    }

    /**
     * Base Primary Info (as User ID, Sequence ID) 를 저장한다.
     *
     * <p><strong>주의사항</strong></br>
     * 1) userSequenceIndex 가 null 이면 안된다.</br>
     * 2) (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     *
     * @param userSequenceIndex Base Primary Info 값
     */
    public void setBasePrimaryInfo(String userSequenceIndex) {
        if (userSequenceIndex == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userSequenceIndex is null");
            return;
        }
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return;
        }
        userControl.setBasePrimaryInfo(userSequenceIndex);
    }

    /**
     * 모든 Control Info 정보를 제거한다.
     *
     * <p><strong>주의사항</strong></br>
     * (@{code context == null || uniqueDeviceID == null}) 인 상태에서 setUniqueDeviceID 함수가 호출된 상태이면 안된다.</p>
     */
    public void removeAllControlInfo() {
        if (userControl == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "userControl is null");
            return;
        }
        userControl.removeAllMemberInfo();
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