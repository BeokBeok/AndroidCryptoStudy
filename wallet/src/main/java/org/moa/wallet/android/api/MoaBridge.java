package org.moa.wallet.android.api;

import android.webkit.JavascriptInterface;

public class MoaBridge {
    private MoaECDSAReceiver moaECDSAReceiver;

    public MoaBridge(MoaECDSAReceiver moaECDSAReceiver) {
        this.moaECDSAReceiver = moaECDSAReceiver;
    }

    @JavascriptInterface
    public void generateKeyPair(String prk, String puk) {
        if (moaECDSAReceiver != null)
            moaECDSAReceiver.onSuccessKeyPair(prk, puk);
    }

    @JavascriptInterface
    public void generateSign(String sign) {
        if (moaECDSAReceiver != null)
            moaECDSAReceiver.onSuccessSign(sign);
    }
}
