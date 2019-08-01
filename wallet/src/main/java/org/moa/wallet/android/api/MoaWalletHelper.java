package org.moa.wallet.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebView;

import org.moa.wallet.manager.Wallet;

import java.util.HashMap;

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
    public void setContext(@NonNull Context context) {
        wallet.setContext(context);
    }

    /**
     * MoaWalletLibReceiver 를 설정한다.
     *
     * @param receiver MoaWalletLibReceiver
     */
    public void setReceiver(@NonNull MoaWalletLibReceiver receiver) {
        wallet.setReceiver(receiver);
    }

    /**
     * Javascript 라이브러리를 사용하기 위한 WebView 를 설정한다.
     *
     * @param webView WebView
     */
    public void setWebView(@NonNull WebView webView) {
        wallet.setWebView(webView);
    }

    /**
     * 지갑을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibWalletCreated 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) setWebView 가 호출된 상태이어야 한다.</br>
     * 2) setReceiver 가 호출된 상태이어야 한다.</p>
     *
     * @param password 지갑 생성 시 사용될 패스워드
     */
    public void createWallet(@NonNull String password) {
        wallet.create(password);
    }

    /**
     * 트랜젝션 서명을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibSignCreated 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) setWebView 가 호출된 상태이어야 한다.</br>
     * 2) setReceiver 가 호출된 상태이어야 한다.</p>
     *
     * @param transaction 서명할 트랜젝션
     * @param password    개인키로 서명하기 위한 패스워드
     */
    public void getSignedTransaction(
            @NonNull String transaction,
            @NonNull String password
    ) {
        wallet.generateSignedTransaction(transaction, password);
    }

    /**
     * 트랜젝션 서명을 검증한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibSignVerify 콜백이 호출된다.</p>
     * <p><strong>주의사항</strong></br>
     * 1) setWebView 가 호출된 상태이어야 한다.</br>
     * 2) setReceiver 가 호출된 상태이어야 한다.</p>
     *
     * @param transaction 서명 검증할 트랜젝션 원문
     * @param sign        서명 값
     */
    public void verifySign(
            @NonNull String transaction,
            @NonNull String sign
    ) {
        wallet.verifiedSign(transaction, sign);
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
     * 1) setWebView 가 호출된 상태이어야 한다.</br>
     * 2) setReceiver 가 호출된 상태이어야 한다.</p>
     *
     * @param password 복구 메시지를 복호화하기 위해 필요한 패스워드
     * @param msg      지갑 복구 메시지
     */
    public void restoreWallet(
            @NonNull String password,
            @NonNull String msg
    ) {
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
    public String getHmacPsw(@NonNull String psw) {
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
    public String getEncryptedHmacPsw(
            @NonNull String id,
            @NonNull String psw,
            @NonNull String dateOfBirth
    ) {
        return Base64.encodeToString(
                wallet.getEncryptedHmacPsw(id, psw, dateOfBirth),
                Base64.NO_WRAP
        );
    }

    /**
     * 패스워드 초기화 메시지를 생성한다.
     *
     * <p><strong>주의사항</strong></br>
     * setPswInitMode(true) 함수가 호출된 상태여야 한다.</p>
     *
     * @param walletData 지갑 패스워드 초기화를 위한 데이터
     *                   server - encryptedHmacPsw, restoreMsg [E(Prk) $ E(Puk) $ Salt],
     *                   client - id, psw, dateOfBirth
     */
    public String generateWalletInitMsg(@NonNull HashMap<String, String> walletData) {
        if (walletData.size() != 5) {
            Log.d("MoaLib", "walletData not validate");
            return "";
        }
        return wallet.generateBackUpRestoreDataFormat(walletData);
    }

    /**
     * 패스워드 초기화된 지갑 데이터로 갱신한다.
     *
     * <p><strong>주의사항</strong></br>
     * setPswInitMode(true) 함수가 호출된 상태여야 한다.</p>
     */
    public void updateWallet() {
        wallet.updateWallet();
    }

    /**
     * 패스워드 초기화 시 미리 생성된 지갑을 제거한다.
     */
    public void removeTempWallet() {
        wallet.removeTempWallet();
    }

    /**
     * Hex String 을 byte[] 로 변환한다.
     *
     * <p>자바스크립트에서 생성된 데이터는 Hex String 이므로, byte 배열로 변환이 필요하다</p>
     *
     * @param target byte[]로 변환할 Hex String
     * @return 변환된 byte 배열
     */
    public byte[] hexStringToByteArray(@NonNull String target) {
        return MoaCommon.getInstance().hexStringToByteArray(target);
    }

    /**
     * Byte[] 를 Hex String 으로 변환한다.
     *
     * <p>자바스크립트에서는 Hex String 을 사용하므로, Hex String 으로 변환이 필요하다.</p>
     *
     * @param target Hex String 으로 변환할 byte[]
     * @return 변환된 Hex String
     */
    public String byteArrayToHexString(@NonNull byte[] target) {
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
