package org.moa.wallet.android.api;

public interface MoaWalletReceiver {
    void onSuccessKeyPair(String prk, String puk);
    
    void onSuccessSign(String sign);

    void onSuccessVerify(boolean checkSign);
}
