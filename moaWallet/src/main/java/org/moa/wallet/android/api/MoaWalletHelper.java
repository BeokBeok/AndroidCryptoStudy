package org.moa.wallet.android.api;

import android.content.Context;
import android.webkit.WebView;

import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.wallet.manager.Wallet;

import java.security.PublicKey;

public class MoaWalletHelper {
    private Wallet wallet;

    private MoaWalletHelper(Builder builder) {
        wallet = new Wallet.Builder(builder.context).addReceiver(builder.receiver).build();
        if (builder.webView != null)
            wallet.setWebView(builder.webView);
    }

    public void createOrGenerateInfoByTypeJS(String password) {
        wallet.generateInfoJS(password);
    }

    public void getSignedTransactionDataJS(String transaction, String password) {
        wallet.generateSignedTransactionDataJS(transaction, password);
    }

    public String getPublicKeyJS() {
        return wallet.getPublicKeyJS();
    }

    public void createRestoreInfoJS(String password, String msg) {
        wallet.setRestoreInfo(password, msg);
    }

    public String getAddress() {
        return wallet.getAddress();
    }

    public void removeWallet() {
        wallet.removeWallet();
    }

    public byte[] hexStringToByteArray(String target) {
        return wallet.hexStringToByteArray(target);
    }

    public String byteArrayToHexString(byte[] target) {
        return wallet.byteArrayToHexString(target);
    }

    @Deprecated
    public void generateInfo(String password) {
        wallet.generateInfo(password);
    }

    @Deprecated
    public byte[] getSignedTransactionData(String transaction, String password) {
        return wallet.generateSignedTransactionData(transaction, password);
    }

    @Deprecated
    public PublicKey getPublicKey() {
        return wallet.getPublicKey();
    }

    @Deprecated
    public boolean verifySignedTransactionData(String plainText, String signedData) {
        return wallet.verifySignedData(plainText, MoaBase58.decode(signedData));
    }

    @Deprecated
    public void verifySignedTransactionDataJS(String plainText, String signedData) {
        wallet.verifySignedDataJS(plainText, signedData);
    }

    public static class Builder {
        private static MoaWalletHelper instance;
        private Context context;
        private WebView webView;
        private MoaWalletLibReceiver receiver;

        public Builder(Context context) {
            this.context = context;
        }

        public Builder addWebView(WebView webView) {
            this.webView = webView;
            return this;
        }

        public Builder addReceiver(MoaWalletLibReceiver receiver) {
            this.receiver = receiver;
            return this;
        }

        public MoaWalletHelper build() {
            if (instance == null)
                instance = new MoaWalletHelper(this);
            return instance;
        }
    }
}
