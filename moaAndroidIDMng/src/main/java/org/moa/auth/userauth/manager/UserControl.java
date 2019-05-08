package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.android.api.MoaCommonable;
import org.moa.auth.userauth.android.api.MoaConfigurable;
import org.moa.auth.userauth.android.api.MoaMember;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.crypto.Cipher;

public class UserControl extends PINAuth implements MoaCommonable {

    private UserControl() {
    }

    public static UserControl getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
        if (uniqueDeviceID != null && uniqueDeviceID.length() > 0)
            setValuesInPreferences(MoaConfigurable.KEY_UNIQUE_DEVICE_INFO, uniqueDeviceID);
    }

    @Override
    public void setValuesInPreferences(String key, String value) {
        String encodedBase64Encryption = "";
        try {
            byte[] encodedUtf8Content = value.getBytes(MoaCommonable.FORMAT_ENCODE);
            byte[] encryption = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, encodedUtf8Content);
            encodedBase64Encryption = Base64.encodeToString(encryption, Base64.NO_WRAP);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][setValuesInPreferences] failed to encode utf8");
        }
        if (encodedBase64Encryption.length() == 0)
            return;
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encodedBase64Encryption);
        editor.apply();
    }

    @Override
    public String getValuesInPreferences(String key) {
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            return "";
        byte[] decodedBase64Value = Base64.decode(value, Base64.NO_WRAP);
        byte[] decryption = symmetricCrypto.getSymmetricData(Cipher.DECRYPT_MODE, decodedBase64Value);
        String encodedUtf8Value = "";
        try {
            encodedUtf8Value = new String(decryption, MoaCommonable.FORMAT_ENCODE);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][getValuesInPreferences] failed to encode utf8");
        }
        return encodedUtf8Value;
    }

    public boolean existPreferences() {
        String controlInfoData = getValuesInPreferences(MoaConfigurable.KEY_CONTROL_INFO);
        return controlInfoData.length() > 0;
    }

    public void setMemberInfo(List<String> data) {
        try {
            String MEMBER_TYPE = data.get(0);
            String MEMBER_ID = data.get(1);
            String AUTH_TYPE = data.get(2);
            String COIN_STORE_TYPE = data.get(3);
            String controlDataForm = MEMBER_TYPE + "$" +
                    Base64.encodeToString(MEMBER_ID.getBytes(MoaCommonable.FORMAT_ENCODE), Base64.NO_WRAP) + "$" +
                    AUTH_TYPE + "$" +
                    COIN_STORE_TYPE;
            setValuesInPreferences(MoaConfigurable.KEY_CONTROL_INFO, controlDataForm);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][setMemberInfo] failed to set member info");
        }
    }

    public String getMemberInfo(String type) {
        String idManagerContent = getValuesInPreferences(MoaConfigurable.KEY_CONTROL_INFO);
        String result = "";
        if (!checkData(idManagerContent))
            return result;
        try {
            StringTokenizer stringTokenizer = new StringTokenizer(idManagerContent, "$");
            String memberType = stringTokenizer.nextToken();
            String base64MemberID = stringTokenizer.nextToken();
            byte[] decodeBase64MemberID = Base64.decode(base64MemberID, Base64.NO_WRAP);
            String memberID = new String(decodeBase64MemberID, MoaCommonable.FORMAT_ENCODE);
            String memberAuthType = stringTokenizer.nextToken();
            String memberCoinKeyMgrType = stringTokenizer.nextToken();

            if (type.equals(MoaMember.Get.MEMBER.getType()))
                result = memberType;
            else if (type.equals(MoaMember.Get.MEMBER_ID.getType()))
                result = memberID;
            else if (type.equals(MoaMember.Get.MEMBER_AUTH.getType()))
                result = memberAuthType;
            else if (type.equals(MoaMember.Get.MEMBER_COIN_KEY_MGR.getType()))
                result = memberCoinKeyMgrType;
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][getMemberInfo] failed to get member info");
        }
        return result;
    }

    public void removeAllMemberInfo() {
        SharedPreferences pref = context.getSharedPreferences(MoaConfigurable.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        pref.edit().clear().apply();
    }

    private boolean checkData(String data) {
        StringTokenizer stringTokenizer = new StringTokenizer(data, "$");
        ArrayList<String> controlInfoArray = new ArrayList<>();
        while (stringTokenizer.hasMoreElements()) {
            controlInfoArray.add(stringTokenizer.nextToken());
        }
        if (controlInfoArray.size() != 4) {
            Log.d("MoaLib", "[UserControl][checkData] Data not validate");
            return false;
        }
        return true;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserControl instance = new UserControl();
    }
}