package org.moa.wallet.android.api;

import android.webkit.JavascriptInterface;

public class MoaBridge implements MoaECDSAReceiver {
    private MoaECDSAReceiver moaECDSAReceiver;

    public MoaBridge(MoaECDSAReceiver moaECDSAReceiver) {
        this.moaECDSAReceiver = moaECDSAReceiver;
    }

    @JavascriptInterface
    public void generateKeyPair(String prk, String puk) {
        onSuccessKeyPair(prk, puk);
    }

    @JavascriptInterface
    public void generateSign(String sign) {
        onSuccessSign(sign);
    }

    @JavascriptInterface
    public void verifySign(String verificationResult) {
        onSuccessVerify(Boolean.parseBoolean(verificationResult));
    }

    @Override
    public void onSuccessKeyPair(String prk, String puk) {
        if (moaECDSAReceiver != null)
            moaECDSAReceiver.onSuccessKeyPair(prk, puk);
    }

    @Override
    public void onSuccessSign(String sign) {
        if (moaECDSAReceiver != null)
            moaECDSAReceiver.onSuccessSign(sign);
    }

    @Override
    public void onSuccessVerify(boolean checkSign) {
        if (moaECDSAReceiver != null)
            moaECDSAReceiver.onSuccessVerify(checkSign);
    }
}
