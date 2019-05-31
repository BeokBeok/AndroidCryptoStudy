package org.moa.wallet.android.api;

public interface MoaWalletLibReceiver {
    void onLibCompleteWallet();

    void onLibCompleteSign(String sign);

    @Deprecated
    void onLibCompleteVerify(boolean checkSign);

    void onLibCompleteRestoreMsg(String msg);
}
