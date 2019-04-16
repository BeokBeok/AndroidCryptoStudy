package org.moa.auth.userauth.android.api;

public interface MoaPreferences {
    String PREFNAME_CONTROL_INFO = "androidIDManager";
    String KEY_CONTROL_INFO = "Control.Info";
    String KEY_UNIQUE_DEVICE_INFO = "UniqueDevice.Info";
    String KEY_AUTO_LOGIN = "Auto.Info";
    String KEY_AUTO_SALT = "Salt.Info";
    String KEY_BASE_PRIMARY_INDEX = "BasePrimary.Info";

    String PREFNAME_AUTH_TOKEN = "androidAuthToken";
    String KEY_AUTH_TOKEN = "AuthToken.Info";

    void setValuesInPreferences(String key, String value);

    String getValuesInPreferences(String key);
}
