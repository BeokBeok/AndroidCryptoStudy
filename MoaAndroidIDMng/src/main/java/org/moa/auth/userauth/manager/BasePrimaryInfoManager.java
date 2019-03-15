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
    public void setValuesInPreference(String key, String value) {
        super.setValuesInPreference(key, value);
    }

    @Override
    public String getValuesInPreference(String key) {
        return super.getValuesInPreference(key);
    }

    public void setBasePrimaryInfo(String basePrimaryInfo) {
        setValuesInPreference(SharedPreferencesManager.KEY_BASE_PRIMARY_INDEX, basePrimaryInfo);
    }

    public String getBasePrimaryInfo() {
        return getValuesInPreference(SharedPreferencesManager.KEY_BASE_PRIMARY_INDEX);
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final BasePrimaryInfoManager instance = new BasePrimaryInfoManager();
    }
}
