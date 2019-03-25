package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;

public class BasePrimary extends UserControl {
    private BasePrimary() {
        super();
    }

    public static BasePrimary getInstance() {
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
        setValuesInPreferences(MoaPreferences.KEY_BASE_PRIMARY_INDEX, basePrimaryInfo);
    }

    public String getBasePrimaryInfo() {
        return getValuesInPreferences(MoaPreferences.KEY_BASE_PRIMARY_INDEX);
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final BasePrimary instance = new BasePrimary();
    }
}
