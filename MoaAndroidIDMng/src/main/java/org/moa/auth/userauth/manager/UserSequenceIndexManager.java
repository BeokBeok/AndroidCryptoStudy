package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;

public class UserSequenceIndexManager extends ControlInfoManager {
    private UserSequenceIndexManager() {
        super();
    }

    public static UserSequenceIndexManager getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
    }

    @Override
    public void setValuesInPreference(String key, String value) {
        super.setValuesInPreference(key, value);
    }

    @Override
    public String getValuesInPreference(String key) {
        return super.getValuesInPreference(key);
    }

    public void setUserSequenceIndex(String userSequenceIndex) {
        setValuesInPreference(SharedPreferencesManager.KEY_USER_SEQUENCE_INDEX, userSequenceIndex);
    }

    public String getUserSequenceIndex() {
        return getValuesInPreference(SharedPreferencesManager.KEY_USER_SEQUENCE_INDEX);
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserSequenceIndexManager instance = new UserSequenceIndexManager();
    }
}
