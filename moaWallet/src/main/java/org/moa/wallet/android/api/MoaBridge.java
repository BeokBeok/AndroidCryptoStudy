package org.moa.wallet.android.api;

import android.webkit.JavascriptInterface;

public class MoaBridge implements MoaWalletReceiver {
    private MoaWalletReceiver moaWalletReceiver;

    public MoaBridge(MoaWalletReceiver moaWalletReceiver) {
        this.moaWalletReceiver = moaWalletReceiver;
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
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessKeyPair(prk, puk);
    }

    @Override
    public void onSuccessSign(String sign) {
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessSign(sign);
    }

    @Override
    public void onSuccessVerify(boolean checkSign) {
        if (moaWalletReceiver != null)
            moaWalletReceiver.onSuccessVerify(checkSign);
    }
}
