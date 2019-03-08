package org.moa.auth.userauth.android.api;

public interface SharedPreferencesManager {
    String PREFNAME_CONTROL_INFO = "androidIDManager";
    String PREFNAME_AUTH_TOKEN = "androidAuthToken";
    String KEY_CONTROL_INFO = "Control.Info";
    String KEY_AUTO_LOGIN = "Auto.Info";
    String KEY_AUTO_SALT = "Salt.Info";
    String KEY_AUTH_TOKEN = "AuthToken.Info";

    void setValuesInPreference(String key, String value);

    String getValuesInPreference(String key);
}
