package org.moa.auth.userauth.android.api;

/**
 * 인증 결과 코드
 */
public enum MoaAuthResultCode {
    /** 아이디 존재 */
    COMMON_ID_EXIST("0x5011"),
    /** 아이디 존재하지 않음 */
    COMMON_ID_NOT_EXIST("0x5012"),
    /** PIN 등록 성공 */
    REGIST_PIN_SUCCESS("0x5021"),
    /** PIN 등록 실패 */
    REGIST_PIN_FAIL("0x5022"),
    /** 지문 등록 시, 인증 토큰 존재 */
    REGIST_FINGER_AUTHTOKEN_EXIST("0x5031"),
    /** 지문 등록 시, 인증 토큰 존재하지 않음 */
    REGIST_FINGER_AUTHTOKEN_NOT_EXIST("0x5032"),
    /** 지문 등록 성공 */
    REGIST_FINGER_SUCCESS("0x5033"),
    /** 지문 등록 실패 */
    REGIST_FINGER_FAIL("0x5034"),
    /** PIN 로그인 시, NONCE 검증 성공 */
    LOGIN_PIN_NONCE_VERIFY("0x5041"),
    /** PIN 로그인 시, NONCE 검증 실패 */
    LOGIN_PIN_NONCE_NOT_VERIFY("0x5042"),
    /** PIN 로그인 성공 */
    LOGIN_PIN_SUCCESS("0x5043"),
    /** PIN 로그인 실패 */
    LOGIN_PIN_FAIL("0x5044"),
    /** 지문 로그인 성공 */
    LOGIN_FINGER_SUCCESS("0x5051"),
    /** 지문 로그인 실패 */
    LOGIN_FINGER_FAIL("0x5052"),
    /** 회원탈퇴 성공 */
    WITHDRAWAL_SUCCESS("0x5061"),
    /** 회원탈퇴 실패 */
    WITHDRAWAL_FAIL("0x5062"),
    /** 패스워드 재설정 성공 */
    RESET_PW_SUCCESS("0x5071"),
    /** 패스워드 재설정 실패 */
    RESET_PW_FAIL("0x5072"),
    /** 패스워드 변경 시, 현재 비밀번호 검증 성공 */
    CHANGE_PW_CURRENT_PW_VERIFY("0x5081"),
    /** 패스워드 변경 시, 현재 비밀번호 검증 실패 */
    CHANGE_PW_CURRENT_PW_NOT_VERIFY("0x5082"),
    /** 패스워드 변경 성공 */
    CHANGE_PW_SUCCESS("0x5083"),
    /** 패스워드 변경 실패 */
    CHANGE_PW_FAIL("0x5084"),
    /** 복원형 지갑 등록 성공 */
    REGIST_RESTORE_WALLET_SUCCESS("0x5091"),
    /** 복원형 지갑 등록 실패 */
    REGIST_RESTORE_WALLET_FAIL("0x5092"),
    /** 복원형 지갑 등록 시, 서버에 등록된 지갑이 존재 */
    REGIST_RESTORE_WALLET_EXIST("0x5093"),
    /** 생성된 지갑 서명 검증 성공 */
    REGIST_RESTORE_WALLET_VERIFY_SUCCESS("0x5095"),
    /** 생성된 지갑 서명 검증 실패 */
    REGIST_RESTORE_WALLET_VERIFY_FAIL("0x5095"),
    /** 지갑 복원 시, 서버에 등록된 지갑 정보 가져오기 성공 */
    RESTORE_WALLET_IMPORT_SUCCESS("0x509A"),
    /** 지갑 복원 시, 서버에 등록된 지갑 정보 가져오기 실패 */
    RESTORE_WALLET_IMPORT_FAIL("0x509B"),
    /** 지갑 복원 성공 */
    RESTORE_WALLET_SUCCESS("0x509C"),
    /** 지갑 복원 실패 */
    RESTORE_WALLET_FAIL("0x509D"),
    /** 지갑 패스워드 재설정을 위한 데이터 가져오기 성공 */
    INIT_WALLET_PSW_DATA_IMPORT_SUCCESS("0x5111"),
    /** 지갑 패스워드 재설정을 위한 데이터 가져오기 성공 */
    INIT_WALLET_PSW_DATA_IMPORT_FAIL("0x5112");

    private String authCode;

    MoaAuthResultCode(String authCode) {
        this.authCode = authCode;
    }

    /**
     * 인증 결과 코드를 리턴한다.
     *
     */
    public String getAuthCode() {
        return authCode;
    }
}
