package org.moa.wallet.android.api;

/**
 * MoaWalletHelper 에서 사용되는 콜백 리스트
 *
 * @author 강현석
 */
public interface MoaWalletLibReceiver {
    /**
     * 지갑을 생성한 후, 서버에 등록할 복원형 지갑 메시지를 생성한다.
     *
     * @param msg 서버에 지갑 등록 시 필요한 메시지</br>
     *            Example:</br>
     *            Base64[E(Prk)]$Base64[E(Puk)]$Base64[Salt]
     */
    void onLibWalletCreated(String msg);

    /**
     * 지갑 복원 완료 시 호출된다.
     */
    void onLibRestoreCompleted();

    /**
     * 서명 생성 완료 시 호출된다.
     *
     * <p>생성된 서명 값은 파라미터에 전달된다.</p>
     *
     * @param sign 생성이 완료된 서명 값
     */
    void onLibSignCreated(String sign);


    /**
     * 전자지갑 관련하여 실패 시 Exception 을 던진다.
     *
     * <p>생성된 Exception 이 파라미터로 전달된다.</p>
     *
     * @param t Exception</br>
     */
    void onLibFail(Throwable t);
}
