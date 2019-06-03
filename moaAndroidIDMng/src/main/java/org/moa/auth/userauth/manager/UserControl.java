package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.android.api.MoaMember;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.crypto.Cipher;

public class UserControl extends PINAuth {

    private UserControl() {
    }

    public static UserControl getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
        if (uniqueDeviceID != null && uniqueDeviceID.length() > 0)
            setValuesInPreferences("UniqueDevice.Info", uniqueDeviceID);
    }

    public boolean existPreferences() {
        String controlInfoData = getValuesInPreferences("Control.Info");
        return controlInfoData.length() > 0;
    }

    public void setMemberInfo(String id, MoaMember moaMember) {
        String controlDataForm = moaMember.getMemberType() + "$" +
                Base64.encodeToString(id.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP) + "$" +
                moaMember.getAuthType() + "$" +
                moaMember.getWalletType();
        setValuesInPreferences("Control.Info", controlDataForm);
    }

    public String getMemberInfo(int type) {
        String idManagerContent = getValuesInPreferences("Control.Info");
        String result = "";
        if (!checkData(idManagerContent))
            return result;
        StringTokenizer stringTokenizer = new StringTokenizer(idManagerContent, "$");
        String memberType = stringTokenizer.nextToken();
        String base64MemberID = stringTokenizer.nextToken();
        byte[] decodeBase64MemberID = Base64.decode(base64MemberID, Base64.NO_WRAP);
        String id = new String(decodeBase64MemberID, StandardCharsets.UTF_8);
        String authType = stringTokenizer.nextToken();
        String walletType = stringTokenizer.nextToken();

        switch (type) {
            case 0:
                return memberType;
            case 1:
                return id;
            case 2:
                return authType;
            case 3:
                return walletType;
            default:
                return "";
        }
    }

    public String getBasePrimaryInfo() {
        return getValuesInPreferences("BasePrimary.Info");
    }

    public void setBasePrimaryInfo(String basePrimaryInfo) {
        setValuesInPreferences("BasePrimary.Info", basePrimaryInfo);
    }

    public void removeAllMemberInfo() {
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        pref.edit().clear().apply();
    }

    private void setValuesInPreferences(String key, String value) {
        assert key != null && value != null;

        String encodedBase64Encryption;
        byte[] encodedUtf8Content = value.getBytes(StandardCharsets.UTF_8);
        byte[] encryption = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, encodedUtf8Content);
        encodedBase64Encryption = Base64.encodeToString(encryption, Base64.NO_WRAP);
        if (encodedBase64Encryption.length() == 0)
            return;
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encodedBase64Encryption);
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        assert key != null;

        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            return "";
        byte[] decodedBase64Value = Base64.decode(value, Base64.NO_WRAP);
        byte[] decryption = symmetricCrypto.getSymmetricData(Cipher.DECRYPT_MODE, decodedBase64Value);
        return new String(decryption, StandardCharsets.UTF_8);
    }

    private boolean checkData(String data) {
        assert data != null;

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