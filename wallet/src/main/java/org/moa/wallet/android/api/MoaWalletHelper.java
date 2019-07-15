package org.moa.wallet.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebView;

import org.moa.wallet.manager.Wallet;

/**
 * 전자지갑 관련 생성 및 복원을 도와준다.
 *
 * <p>지갑 생성 및 복원을 지원한다.</p>
 * <p>문제 발생 시 {@literal "MoaLib"} 로그를 참고한다.</p>
 * <p><strong>주의사항</strong></br>
 * getInstance 함수 호출 후, setContext/setReceiver/setWebView 함수를 호출해야만</br>
 * MoaWalletHelper 인스턴스를 정상적으로 이용이 가능하다.</p>
 *
 * @author 강현석
 */
public class MoaWalletHelper {
    private Wallet wallet;

    private MoaWalletHelper() {
        wallet = Wallet.getInstance();
    }

    /**
     * MoaWalletHelper 객체를 반환한다.
     */
    public static MoaWalletHelper getInstance() {
        return Singleton.instance;
    }

    /**
     * Context 를 설정한다.
     *
     * @param context 해당 Activity 의 Context
     */
    public void setContext(Context context) {
        wallet.setContext(context);
    }

    /**
     * MoaWalletLibReceiver 를 설정한다.
     *
     * <p><strong>주의사항</strong></br>
     * ({@code receiver == null}) 이면 안된다.</p>
     *
     * @param receiver MoaWalletLibReceiver
     */
    public void setReceiver(MoaWalletLibReceiver receiver) {
        if (receiver == null) {
            Log.d("MoaLib", "receiver is null");
            return;
        }
        wallet.setReceiver(receiver);
    }

    /**
     * Javascript 라이브러리를 사용하기 위한 WebView 를 설정한다.
     *
     * <p><strong>주의사항</strong></br>
     * ({@code webView == null}) 이면 안된다.</p>
     *
     * @param webView WebView
     */
    public void setWebView(WebView webView) {
        if (webView == null) {
            Log.d("MoaLib", "webView is null");
            return;
        }
        wallet.setWebView(webView);
    }

    /**
     * 지갑을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibWalletCreated 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) ({@code webView == null}) 인 상태로 setWebView 가 호출된 상태이면 안된다.</br>
     * 2) ({@code receiver == null}) 인 상태로 setReceiver 가 호출된 상태이면 콜백이 발생하지 않는다.</p>
     * 3) ({@code password == null}) 이면 안된다.</p>
     *
     * @param password 지갑 생성 시 사용될 패스워드
     */
    public void createWallet(String password) {
        if (password == null) {
            Log.d("MoaLib", "password is null");
            return;
        }
        wallet.create(password);
    }

    /**
     * 트랜젝션 서명을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibSignCreated 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) ({@code webView == null}) 인 상태로 setWebView 가 호출된 상태이면 안된다.</br>
     * 2) ({@code receiver == null}) 인 상태로 setReceiver 가 호출된 상태이면 콜백이 발생하지 않는다.</p>
     * 3) ({@code transaction == null || password == null}) 이면 안된다.</p>
     *
     * @param transaction 서명할 트랜젝션
     * @param password    개인키로 서명하기 위한 패스워드
     */
    public void getSignedTransaction(String transaction, String password) {
        if (transaction == null) {
            Log.d("MoaLib", "transaction is null");
            return;
        }
        if (password == null) {
            Log.d("MoaLib", "password is null");
            return;
        }
        wallet.generateSignedTransaction(transaction, password);
    }

    /**
     * 서명 검증 시 필요한 공개키를 리턴한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     */
    public String getPublicKey() {
        return wallet.getPublicKey();
    }

    /**
     * 지갑 복구 할 때, 복구 메시지를 기반으로 복구한다.
     *
     * <p>완료 시 onLibRestoreCompleted 콜백이 호출된다.</p>
     * <p>지갑 비밀번호 불일치 시 onLibFail 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) ({@code context == null}) 인 상태로 setWebView 가 호출된 상태이면 안된다.</br>
     * 2) ({@code receiver == null}) 인 상태로 setReceiver 가 호출된 상태이면 콜백이 발생하지 않는다.</p>
     * 3) ({@code transaction == null || password == null}) 이면 안된다.</p>
     *
     * @param password 복구 메시지를 복호화하기 위해 필요한 패스워드
     * @param msg      지갑 복구 메시지
     */
    public void restoreWallet(String password, String msg) {
        if (password == null) {
            Log.d("MoaLib", "password is null");
            return;
        }
        if (msg == null) {
            Log.d("MoaLib", "msg is null");
            return;
        }
        if (wallet.verifyPsw(password, msg)) { // onLibRestoreCompleted
            String[] restoreMsg = msg.split("%");
            wallet.save(password, restoreMsg[1]);
        } else { // onLibFail 호출
            wallet.throwWalletException(
                    new IllegalStateException(MoaWalletErr.RESTORE_PASSWORD_NOT_VERIFY.getType())
            );
        }
    }

    /**
     * 지갑 주소를 리턴한다.
     */
    public String getAddress() {
        return wallet.getAddress();
    }

    /**
     * 지갑 정보를 제거한다.
     */
    public void removeWallet() {
        wallet.removeWallet();
    }

    /**
     * 패스워드를 HMAC 처리한 데이터를 리턴한다.
     *
     * @param psw 패스워드
     */
    public String getHmacPsw(String psw) {
        return MoaCommon.getInstance()
                .byteArrayToHexString(wallet.getHmacPsw(psw));
    }

    /**
     * 패스워드를 HMAC 처리한 데이터를 암호화한 값을 리턴한다.
     *
     * @param id          사용자 id
     * @param psw         패스워드
     * @param dateOfBirth 생년월일; 패스워드 암호화 시 Key로 사용된다.
     */
    public String getEncryptedHmacPsw(String id, String psw, String dateOfBirth) {
        return Base64.encodeToString(
                wallet.getEncryptedHmacPsw(id, psw, dateOfBirth),
                Base64.NO_WRAP
        );
    }

    /**
     * Hex String 을 byte[] 로 변환한다.
     *
     * <p>자바스크립트에서 생성된 데이터는 Hex String 이므로, byte 배열로 변환이 필요하다</p>
     * <p><strong>주의사항</strong></br>
     * ({@code target == null}) 이면 안된다.</p>
     *
     * @param target byte[]로 변환할 Hex String
     * @return 변환된 byte 배열
     */
    public byte[] hexStringToByteArray(String target) {
        if (target == null) {
            Log.d("MoaLib", "target is null");
            return new byte[0];
        }
        return MoaCommon.getInstance().hexStringToByteArray(target);
    }

    /**
     * Byte[] 를 Hex String 으로 변환한다.
     *
     * <p>자바스크립트에서는 Hex String 을 사용하므로, Hex String 으로 변환이 필요하다.</p>
     * <p><strong>주의사항</strong></br>
     * ({@code target == null}) 이면 안된다.</p>
     *
     * @param target Hex String 으로 변환할 byte[]
     * @return 변환된 Hex String
     */
    public String byteArrayToHexString(byte[] target) {
        if (target == null) {
            Log.d("MoaLib", "target is null");
            return "";
        }
        return MoaCommon.getInstance().byteArrayToHexString(target);
    }

    /**
     * 싱글 인스턴스 생성을 도와준다.
     *
     * <p>MoaWalletHelper 인스턴스를 한 번만 생성한다.</br>
     * 이너클래스에서 인스턴스를 생성하므로 스레드에 안전하다.
     * </p>
     */
    public static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static MoaWalletHelper instance = new MoaWalletHelper();
    }
}
