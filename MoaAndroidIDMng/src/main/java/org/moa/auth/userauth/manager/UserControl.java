package org.moa.auth.userauth.manager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.moa.auth.userauth.android.api.Member;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class UserControl extends PINAuthentication {

    UserControl() {
    }

    public static UserControl getInstance() {
        return Singleton.instance;
    }

    @Override
    public void init(Context context, String uniqueDeviceID) {
        super.init(context, uniqueDeviceID);
    }

    @Override
    public void setValuesInPreference(String key, String value) {
        String encryptedData = getEncryptContent(value);
        android.content.SharedPreferences pref = context.getSharedPreferences(SharedPreferencesImpl.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        android.content.SharedPreferences.Editor editor = pref.edit();
        editor.putString(key, encryptedData);
        editor.apply();
    }

    @Override
    public String getValuesInPreference(String key) {
        android.content.SharedPreferences pref = context.getSharedPreferences(SharedPreferencesImpl.PREFNAME_CONTROL_INFO, Context.MODE_PRIVATE);
        String value = pref.getString(key, "");
        if (value == null)
            return "";
        byte[] controlInfo = Base64.decode(value, Base64.NO_WRAP);
        return getDecryptContent(controlInfo);
    }

    public boolean existPreference() {
        String controlInfoData = getValuesInPreference(SharedPreferencesImpl.KEY_CONTROL_INFO);
        return controlInfoData.length() > 0;
    }

    public void setMemberInfo(List<String> data) {
        try {
            String MEMBER_TYPE = data.get(0);
            String MEMBER_ID = data.get(1);
            String AUTH_TYPE = data.get(2);
            String COIN_STORE_TYPE = data.get(3);
            String controlDataForm = MEMBER_TYPE + "$" +
                    Base64.encodeToString(MEMBER_ID.getBytes(FORMAT_ENCODE), Base64.NO_WRAP) + "$" +
                    AUTH_TYPE + "$" +
                    COIN_STORE_TYPE;
            if (MEMBER_TYPE.equals(Member.Type.NONMEMBER.getType())) {
                controlDataForm = MEMBER_TYPE + "$" +
                        MEMBER_ID + "$" +
                        AUTH_TYPE + "$" +
                        COIN_STORE_TYPE;
            }
            setValuesInPreference(SharedPreferencesImpl.KEY_CONTROL_INFO, controlDataForm);
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][setMemberInfo] failed to set member info");
            throw new RuntimeException("Failed to set member info", e);
        }
    }

    public String getMemberInfo(String type) {
        String idManagerContent = getValuesInPreference(SharedPreferencesImpl.KEY_CONTROL_INFO);
        String result = "";
        if (!checkData(idManagerContent))
            return "";
        try {
            StringTokenizer stringTokenizer = new StringTokenizer(idManagerContent, "$");
            String memberType = stringTokenizer.nextToken();
            String base64MemberID = stringTokenizer.nextToken();
            byte[] decodeBase64MemberID = Base64.decode(base64MemberID, Base64.NO_WRAP);
            String memberID = new String(decodeBase64MemberID, FORMAT_ENCODE);
            if (memberType.equals(Member.Type.NONMEMBER.getType()))
                memberID = base64MemberID;
            String memberAuthType = stringTokenizer.nextToken();
            String memberCoinKeyMgrType = stringTokenizer.nextToken();

            if (type.equals(Member.Get.MEMBER.getType()))
                result = memberType;
            else if (type.equals(Member.Get.MEMBER_ID.getType()))
                result = memberID;
            else if (type.equals(Member.Get.MEMBER_AUTH.getType()))
                result = memberAuthType;
            else if (type.equals(Member.Get.MEMBER_COIN_KEY_MGR.getType()))
                result = memberCoinKeyMgrType;
        } catch (UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][getMemberInfo] failed to get member info");
            throw new RuntimeException("Failed to get member info", e);
        }
        return result;
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

    private Cipher getCipher(int mode) {
        String transformation = "DESede/CBC/PKCS5Padding";
        byte[] originUniqueDeviceID = Base64.decode(uniqueDeviceID, Base64.NO_WRAP);
        byte[] keyBytes = new byte[24];
        System.arraycopy(originUniqueDeviceID, 0, keyBytes, 0, keyBytes.length);
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DESede");
            byte[] iv = new byte[cipher.getBlockSize()];
            System.arraycopy(originUniqueDeviceID, keyBytes.length - 1, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                return cipher;
            }
            if (mode == Cipher.DECRYPT_MODE) {
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                return cipher;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            Log.d("MoaLib", "[UserControl][getCipher] failed to get cipher");
            throw new RuntimeException("Failed to get cipher", e);
        }
        return null;
    }

    private String getEncryptContent(String content) {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
        if (cipher == null)
            return "";
        try {
            byte[] encryptContent = cipher.doFinal(content.getBytes(FORMAT_ENCODE));
            return Base64.encodeToString(encryptContent, Base64.NO_WRAP);
        } catch (BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][getEncryptContent] failed to get encrypt content");
            throw new RuntimeException("Failed to get encrypt content", e);
        }
    }

    private String getDecryptContent(byte[] content) {
        if (content.length == 0)
            return "";
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
        if (cipher == null)
            return "";
        try {
            byte[] decryptContent = cipher.doFinal(content);
            return new String(decryptContent, FORMAT_ENCODE);
        } catch (BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            Log.d("MoaLib", "[UserControl][getDecryptContent] failed to get decrypt content");
            throw new RuntimeException("Failed to get decrypt content", e);
        }
    }

    private static class Singleton {
        @SuppressLint("StaticFieldLeak")
        private static final UserControl instance = new UserControl();
    }
}
