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
    public void init(
            Context context,
            String uniqueDeviceID
    ) {
        super.init(context, uniqueDeviceID);
    }

    public void setMemberInfo(
            String id,
            MoaMember moaMember
    ) {
        if (moaMember.getAuthType() == MoaMember.NON_MEMBER.getAuthType()) {
            setValuesInPreferences("NonMemberID", id);
        } else {
            setValuesInPreferences("MemberID", id);
        }
        setValuesInPreferences(
                "Control.Info",
                moaMember.getMemberType() + "$" +
                        Base64.encodeToString(id.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP) + "$" +
                        moaMember.getAuthType() + "$" +
                        moaMember.getWalletType()
        );
    }

    public String getNonMemberID() {
        return getValuesInPreferences("NonMemberID");
    }

    public String getMemberID() {
        return getValuesInPreferences("MemberID");
    }

    public String getMemberInfo(int type) {
        if (type < 0 || type > 3) {
            Log.d("MoaLib", "type is " + type);
            return "";
        }
        String idManagerContent = getValuesInPreferences("Control.Info");
        if (!checkData(idManagerContent)) {
            Log.d("MoaLib", "data is not validate");
            return "";
        }
        StringTokenizer st = new StringTokenizer(idManagerContent, "$");
        String memberType = st.nextToken();
        byte[] decodeBase64MemberID = Base64.decode(st.nextToken(), Base64.NO_WRAP);
        String id = new String(decodeBase64MemberID, StandardCharsets.UTF_8);
        String authType = st.nextToken();
        String walletType = st.nextToken();

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
        SharedPreferences pref =
                context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        pref.edit().remove("Control.Info").apply();
    }

    private void setValuesInPreferences(
            String key,
            String value
    ) {
        SharedPreferences pref =
                context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString(
                key,
                Base64.encodeToString(
                        symmetric.getSymmetricData(
                                Cipher.ENCRYPT_MODE,
                                value.getBytes(StandardCharsets.UTF_8)
                        ),
                        Base64.NO_WRAP
                )
        );
        editor.apply();
    }

    private String getValuesInPreferences(String key) {
        SharedPreferences pref =
                context.getSharedPreferences("androidIDManager", Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null || value.length() == 0) {
            Log.d("MoaLib", "value not validate");
            return "";
        }
        return new String(
                symmetric.getSymmetricData(
                        Cipher.DECRYPT_MODE,
                        Base64.decode(
                                value,
                                Base64.NO_WRAP
                        )
                ),
                StandardCharsets.UTF_8
        );
    }

    private boolean checkData(String data) {
        StringTokenizer stringTokenizer = new StringTokenizer(data, "$");
        ArrayList<String> controlInfoArray = new ArrayList<>();
        while (stringTokenizer.hasMoreElements()) {
            controlInfoArray.add(stringTokenizer.nextToken());
        }
        if (controlInfoArray.size() != 4) {
            Log.d("MoaLib", "data not validate");
            return false;
        }
        return true;
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserControl instance = new UserControl();
    }
}