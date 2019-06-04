package org.moa.wallet.android.api;

/**
 * MoaWalletHelper 에서 사용되는 콜백 리스트
 *
 * @author 강현석
 */
public interface MoaWalletLibReceiver {
    /**
     * 지갑 생성 완료 시 호출된다.
     */
    void onLibCompleteWallet();

    /**
     * 서명 생성 완료 시 호출된다.
     *
     * <p>생성된 서명 값은 파라미터에 전달된다.</p>
     *
     * @param sign 생성이 완료된 서명 값
     */
    void onLibCompleteSign(String sign);

    /**
     * 복원형 지갑 생성 시 필요한 메시지 생성 시 호출된다.
     *
     * <p>서버에 등록하고 지갑 복원 시 필요하다.</p>
     *
     * @param msg 복원형 지갑 생성 시 필요한 메시지</br>
     *            Example:</br>
     *            Base64[E(Prk)]$Base64[E(Puk)]$Base64[Salt]
     */
    void onLibCompleteRestoreMsg(String msg);
}
