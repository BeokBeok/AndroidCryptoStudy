package org.moa.wallet.android.api;

import android.content.Context;
import android.webkit.WebView;

import org.moa.android.crypto.coreapi.MoaBase58;
import org.moa.wallet.manager.Wallet;

import java.security.PublicKey;

public class MoaWalletHelper {
    private Wallet wallet;

    private MoaWalletHelper(Builder builder) {
        wallet = new Wallet.Builder(builder.context).addReceiver(builder.receiver).addType(builder.type).build();
        if (builder.webView != null)
            wallet.setWebView(builder.webView);
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

    public boolean exists() {
        return wallet.existPreferences();
    }

    //TODO 추후 제거
    public String getContent() {
        String versionInfo = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_VERSION_INFO);
        String osInfo = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_OS_INFO);
        String salt = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_SALT);
        String iterationCount = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_ITERATION_COUNT);
        String cipheredData = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_CIPHERED_DATA);
        String walletPuk = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_PUBLIC_KEY);
        String walletAddr = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_ADDRESS);
        String macData = wallet.getValuesInPreferences(MoaConfigurable.KEY_WALLET_MAC_DATA);
        return "Version.Info=" + versionInfo + "\n" +
                "OS.Info=" + osInfo + "\n" +
                "Salt.Value=" + salt + "\n" +
                "Iteration.Count=" + iterationCount + "\n" +
                "Ciphered.Data=" + cipheredData + "\n" +
                "Wallet.PublicKey=" + walletPuk + "\n" +
                "Wallet.Addr=" + walletAddr + "\n" +
                "MAC.Data=" + macData;
    }

    public void createOrGenerateInfoByTypeJS(String password) {
        wallet.generateInfoJS(password);
    }

    public void getSignedTransactionDataJS(String transaction, String password) {
        wallet.generateSignedTransactionDataJS(transaction, password);
    }

    public void verifySignedTransactionDataJS(String plainText, String signedData) {
        wallet.verifySignedDataJS(plainText, signedData);
    }

    public String getPublicKeyJS() {
        return wallet.getPublicKeyJS();
    }

    public void createRestoreInfoJS(String password, String msg) {
        wallet.setRestoreInfo(password, msg);
    }

    public byte[] hexStringToByteArray(String target) {
        return wallet.hexStringToByteArray(target);
    }

    public String byteArrayToHexString(byte[] target) {
        return wallet.byteArrayToHexString(target);
    }

    public String getAddress() {
        return wallet.getAddress();
    }

    public static class Builder {
        private static MoaWalletHelper instance;
        private Context context;
        private WebView webView;
        private String type;
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

        public Builder addType(String type) {
            this.type = type;
            return this;
        }

        public MoaWalletHelper build() {
            return new MoaWalletHelper(this);
        }
    }
}
