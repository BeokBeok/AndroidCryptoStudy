package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.moa.auth.userauth.android.api.MoaCommon;
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
        if (context == null || uniqueDeviceID == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Context or unique device id is null");
        super.init(context, uniqueDeviceID);
        setValuesInPreferences("UniqueDevice.Info", uniqueDeviceID);
    }

    public void setMemberInfo(String id, MoaMember moaMember) {
        if (id == null || moaMember == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "ID or moaMember is null");
        String controlDataForm = moaMember.getMemberType() + "$" +
                Base64.encodeToString(id.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP) + "$" +
                moaMember.getAuthType() + "$" +
                moaMember.getWalletType();
        setValuesInPreferences("Control.Info", controlDataForm);
    }

    public String getMemberInfo(int type) {
        if (type < 0 || type > 3)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Type not validate");
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
        if (key == null || value == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Key or value is null");
        byte[] encodedUtf8Content = value.getBytes(StandardCharsets.UTF_8);
        byte[] encryption = symmetricCrypto.getSymmetricData(Cipher.ENCRYPT_MODE, encodedUtf8Content);
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, Base64.encodeToString(encryption, Base64.NO_WRAP));
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        if (key == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Key is null");
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Value not validate");
        byte[] decodedBase64Value = Base64.decode(value, Base64.NO_WRAP);
        byte[] decryption = symmetricCrypto.getSymmetricData(Cipher.DECRYPT_MODE, decodedBase64Value);
        return new String(decryption, StandardCharsets.UTF_8);
    }

    private boolean checkData(String data) {
        if (data == null)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Data is null");
        StringTokenizer stringTokenizer = new StringTokenizer(data, "$");
        ArrayList<String> controlInfoArray = new ArrayList<>();
        while (stringTokenizer.hasMoreElements()) {
            controlInfoArray.add(stringTokenizer.nextToken());
        }
        if (controlInfoArray.size() != 4)
            throw new RuntimeException(MoaCommon.getInstance().getClassAndMethodName() + "Data not validate");
        return true;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserControl instance = new UserControl();
    }
}