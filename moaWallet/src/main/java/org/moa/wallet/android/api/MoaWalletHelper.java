package org.moa.wallet.android.api;

import android.content.Context;
import android.util.Base64;

import org.moa.wallet.manager.Wallet;

import java.security.PublicKey;

public class MoaWalletHelper {
    private Wallet wallet;

    private MoaWalletHelper(Builder builder) {
        Context context = builder.context;
        wallet = new Wallet.Builder(context).build();
    }

    public void generateWalletInfo(String password) {
        wallet.generateInfo(password);
    }

    public byte[] getSigendTransactionData(String transaction, String password) {
        return wallet.generateSignedTransactionData(transaction, password);
    }

    public PublicKey getWalletPublicKey() {
        return wallet.getPublicKey();
    }

    public boolean verifySignedTransactionData(String plainText, String transactionData) {
        return wallet.verifySignedData(plainText, Base64.decode(transactionData, Base64.NO_WRAP));
    }

    public boolean existWallet() {
        return wallet.existPreferences();
    }

    //TODO 지갑 데이터별로 Getter 함수 구현
    public String getWalletContent() {
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

    public static class Builder {
        private Context context;
        private static MoaWalletHelper instance;

        public Builder(Context context) {
            this.context = context;
        }

        public MoaWalletHelper build() {
            if (instance == null)
                instance = new MoaWalletHelper(this);
            return instance;
        }
    }
}
