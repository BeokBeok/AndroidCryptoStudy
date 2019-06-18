package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.moa.android.crypto.coreapi.CryptoHelper;
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
        if (context == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "context is null");
            return;
        }
        if (uniqueDeviceID == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "uniqueDeviceID is null");
            return;
        }
        super.init(context, uniqueDeviceID);
        setValuesInPreferences("UniqueDevice.Info", uniqueDeviceID);
    }

    public void setMemberInfo(String id, MoaMember moaMember) {
        if (id == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "id is null");
            return;
        }
        if (moaMember == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "moaMember is null");
            return;
        }
        if (moaMember.getAuthType() == MoaMember.NON_MEMBER.getAuthType()) {
            setValuesInPreferences("NonMemberID", id);
        } else {
            setValuesInPreferences("MemberID", id);
        }
        String controlDataForm = moaMember.getMemberType() + "$" +
                Base64.encodeToString(id.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP) + "$" +
                moaMember.getAuthType() + "$" +
                moaMember.getWalletType();
        setValuesInPreferences("Control.Info", controlDataForm);
    }

    public String getNonMemberID() {
        return getValuesInPreferences("NonMemberID");
    }

    public String getMemberID() {
        return getValuesInPreferences("MemberID");
    }

    public String getMemberInfo(int type) {
        if (type < 0 || type > 3) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "type is " + type);
            return "";
        }
        String idManagerContent = getValuesInPreferences("Control.Info");
        if (!checkData(idManagerContent)) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "data is not validate");
            return "";
        }
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

    public void removeControlInfo() {
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        pref.edit().remove("Control.Info").apply();
    }

    private void setValuesInPreferences(String key, String value) {
        if (key == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "key is null");
            return;
        }
        if (value == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "value is null");
            return;
        }
        byte[] encodedUtf8Content = value.getBytes(StandardCharsets.UTF_8);
        setSymmetricCryptoInstance();
        byte[] encryption = CryptoHelper.getInstance().getSymmetricData(Cipher.ENCRYPT_MODE, encodedUtf8Content);
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, Base64.encodeToString(encryption, Base64.NO_WRAP));
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        if (key == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "key is null");
            return "";
        }
        SharedPreferences pref = context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "value not validate");
            return "";
        }
        byte[] decodedBase64Value = Base64.decode(value, Base64.NO_WRAP);
        setSymmetricCryptoInstance();
        byte[] decryption = CryptoHelper.getInstance().getSymmetricData(Cipher.DECRYPT_MODE, decodedBase64Value);
        return new String(decryption, StandardCharsets.UTF_8);
    }

    private boolean checkData(String data) {
        if (data == null) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "data is null");
            return false;
        }
        StringTokenizer stringTokenizer = new StringTokenizer(data, "$");
        ArrayList<String> controlInfoArray = new ArrayList<>();
        while (stringTokenizer.hasMoreElements()) {
            controlInfoArray.add(stringTokenizer.nextToken());
        }
        if (controlInfoArray.size() != 4) {
            Log.d("MoaLib", MoaCommon.getInstance().getClassAndMethodName() + "data not validate");
            return false;
        }
        return true;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserControl instance = new UserControl();
    }
}