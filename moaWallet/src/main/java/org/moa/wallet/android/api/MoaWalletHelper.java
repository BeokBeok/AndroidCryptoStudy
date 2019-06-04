package org.moa.wallet.android.api;

import android.annotation.SuppressLint;
import android.content.Context;
import android.webkit.WebView;

import org.moa.wallet.manager.Wallet;

/**
 * 전자지갑 관련 생성 및 복원을 도와준다.
 *
 * <p>지갑 생성 및 복원을 지원한다.</p>
 *
 * @author 강현석
 */
public class MoaWalletHelper {
    private Wallet wallet;

    private MoaWalletHelper(Builder builder) {
        wallet = new Wallet.Builder(builder.context).addReceiver(builder.receiver).build();
        if (builder.webView != null)
            wallet.setWebView(builder.webView);
    }

    /**
     * 지갑을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibCompleteWallet 콜백이 호출된다.</p>
     *
     * @param password 지갑 생성 시 사용될 패스워드; null 이면 안된다.</br>
     *                 개인키 암호화 시 필요
     * @throws RuntimeException ({@code password == null}) 이면 발생한다.
     */
    public void createWallet(String password) {
        if (password == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Password is null");
        wallet.generateInfo(password);
    }

    /**
     * 트랜젝션 서명을 생성한다.
     *
     * <p>자바스크립트 라이브러리가 사용된다.</p>
     * <p>완료 시 onLibCompleteSign 콜백이 호출된다.</p>
     *
     * @param transaction 서명할 트랜젝션; null 이면 안된다.
     * @param password    개인키로 서명하기 위한 패스워드; null 이면 안된다.
     * @throws RuntimeException ({@code transaction == null || password == null}) 이면 발생한다.
     */
    public void getSignedTransaction(String transaction, String password) {
        if (transaction == null || password == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Transaction or Password is null");
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
     * <p>완료 시 onLibCompleteWallet 콜백이 호출된다.</p>
     *
     * @param password 복구 메시지를 복호화하기 위해 필요한 패스워드; null 이면 안된다.
     * @param msg      지갑 복구 메시지; null 이면 안된다.
     * @throws RuntimeException ({@code password == null || msg == null}) 이면 발생한다.
     */
    public void restoreWallet(String password, String msg) {
        if (password == null || msg == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Password or msg is null");
        wallet.setRestoreInfo(password, msg);
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
     * Hex String 을 byte[] 로 변환한다.
     *
     * <p>자바스크립트에서 생성된 데이터는 Hex String 이므로, byte 배열로 변환이 필요하다</p>
     *
     * @param target byte[]로 변환할 Hex String; null 이면 안된다.
     * @return 변환된 byte 배열
     * @throws RuntimeException ({@code target == null}) 이면 발생한다.
     */
    public byte[] hexStringToByteArray(String target) {
        if (target == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Target is null");
        return wallet.hexStringToByteArray(target);
    }

    /**
     * Byte[] 를 Hex String 으로 변환한다.
     *
     * <p>자바스크립트에서는 Hex String 을 사용하므로, Hex String 으로 변환이 필요하다.</p>
     *
     * @param target Hex String 으로 변환할 byte[]; null 이면 안된다.
     * @return 변환된 Hex String
     * @throws RuntimeException ({code target == null}) 이면 발생한다.
     */
    public String byteArrayToHexString(byte[] target) {
        if (target == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Target is null");
        return wallet.byteArrayToHexString(target);
    }

    /**
     * 빌더를 통하여 인스턴스 생성을 도와준다.
     *
     * <p>MoaWalletHelper 인스턴스가 <i>하나</i>만 생성된다. (싱글턴)</br>
     * Inner class 를 활용하여 인스턴스를 생성하므로 스레드에 안전하다.
     * </p>
     * <p>Example:</br>
     * {@code new MoaWalletHelper.Builder(this).addWebView(webview).addReceiver(this).build()}
     * </p>
     */
    public static class Builder {
        @SuppressLint("StaticFieldLeak")
        private static MoaWalletHelper instance;
        private Context context;
        private WebView webView;
        private MoaWalletLibReceiver receiver;

        /**
         * 빌더 사용을 위한 생성자
         *
         * @param context Shared Preference 를 사용하기 위한 context
         */
        public Builder(Context context) {
            this.context = context;
        }

        /**
         * 자바스크립트 라이브러리를 사용하기 위하여 Web View 를 설정한다.
         *
         * @param webView Web View
         * @return 빌더
         */
        public Builder addWebView(WebView webView) {
            this.webView = webView;
            return this;
        }

        /**
         * 전자지갑 관련 동작을 UI에 알려주기 위하여 리시버를 설정한다.
         *
         * @param receiver MoaWalletLibReceiver
         * @return 빌더
         */
        public Builder addReceiver(MoaWalletLibReceiver receiver) {
            this.receiver = receiver;
            return this;
        }

        /**
         * MoaWalletHelper 인스턴스를 생성한다.
         *
         * @return 생성된 MoaWalletHelper 인스턴스
         */
        public MoaWalletHelper build() {
            if (instance == null && context != null)
                instance = new MoaWalletHelper(this);
            return instance;
        }
    }
}
