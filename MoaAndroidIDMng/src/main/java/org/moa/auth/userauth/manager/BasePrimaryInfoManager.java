package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;

public class BasePrimaryInfoManager extends ControlInfoManager {
    private BasePrimaryInfoManager() {
        super();
    }

    public static BasePrimaryInfoManager getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
    }

    @Override
    public void setValuesInPreferences(String key, String value) {
        super.setValuesInPreferences(key, value);
    }

    @Override
    public String getValuesInPreferences(String key) {
        return super.getValuesInPreferences(key);
    }

    public void setBasePrimaryInfo(String basePrimaryInfo) {
        setValuesInPreferences(SharedPreferencesManager.KEY_BASE_PRIMARY_INDEX, basePrimaryInfo);
    }

    public String getBasePrimaryInfo() {
        return getValuesInPreferences(SharedPreferencesManager.KEY_BASE_PRIMARY_INDEX);
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final BasePrimaryInfoManager instance = new BasePrimaryInfoManager();
    }
}
