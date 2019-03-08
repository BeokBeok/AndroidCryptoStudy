package org.moa.auth.userauth.android.api;

public interface SharedPreferencesManager {
    String PREFNAME_CONTROL_INFO = "androidIDManager";
    String KEY_CONTROL_INFO = "Control.Info";
    String KEY_AUTO_LOGIN = "Auto.Info";
    String KEY_AUTO_SALT = "Salt.Info";

    String PREFNAME_AUTH_TOKEN = "androidAuthToken";
    String KEY_AUTH_TOKEN = "AuthToken.Info";

    String PREFNAME_WALLET = "moaWallet";
    String KEY_WALLET_VERSION_INFO = "Version.Info";
    String KEY_WALLET_OS_INFO = "OS.Info";
    String KEY_WALLET_SYMMETRIC_ALGORITHM = "Symmetric.Alg";
    String KEY_WALLET_SYMMETRIC_KEY_SIZE = "Symmetric.KeySize";
    String KEY_WALLET_HASH_ALGORITHM = "Hash.Alg";
    String KEY_WALLET_SIGNATURE_ALGIROTHM = "Signature.Alg";
    String KEY_WALLET_ECC_ALGORITHM = "ECC.Alg";
    String KEY_WALLET_ECC_CURVE= "ECC.Curve";
    String KEY_WALLET_MAC_ALGORITHM = "MAC.Alg";
    String KEY_WALLET_ITERATION_COUNT = "Iteration.Count";
    String KEY_WALLET_SALT = "Salt.Value";
    String KEY_WALLET_CIPHERED_DATA = "Ciphered.Data";
    String KEY_WALLET_PUBLIC_KEY = "Wallet.PublicKey";
    String KEY_WALLET_ADDRESS = "Wallet.Addr";
    String KEY_WALLET_MAC_DATA = "MAC.Data";

    void setValuesInPreference(String key, String value);

    String getValuesInPreference(String key);
}
