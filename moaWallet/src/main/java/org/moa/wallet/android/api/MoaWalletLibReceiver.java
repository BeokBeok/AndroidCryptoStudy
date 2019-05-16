package org.moa.wallet.android.api;

public interface MoaWalletLibReceiver {
    void onCompleteWallet();

    void onCompleteSign(String sign);

    void onCompleteVerify(boolean checkSign);

    void onCompleteRestoreMsg(String msg);
}
