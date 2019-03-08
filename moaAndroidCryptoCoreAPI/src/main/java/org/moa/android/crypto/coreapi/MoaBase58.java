package org.moa.android.crypto.coreapi;

import java.math.BigInteger;

public class MoaBase58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    /**
     * 바이트 배열을 입력 받아 Base58로 엔코딩하여 문자열로 반환한다.
     * @param input MoaBase58 문자열로 변환할 바이트 배열 입력
     * @return String MoaBase58 변환 문자열 반환
     */
    public static String encode(byte[] input)
    {
        // This could be a lot more efficient.
        BigInteger bigInteger = new BigInteger(1, input);
        StringBuilder stringBuilder = new StringBuilder();

        while (bigInteger.compareTo(BASE) >= 0) {
            BigInteger mod = bigInteger.mod(BASE);
            stringBuilder.insert(0, ALPHABET.charAt(mod.intValue()));
            bigInteger = bigInteger.subtract(mod).divide(BASE);
        }

        stringBuilder.insert(0, ALPHABET.charAt(bigInteger.intValue()));

        // Convert leading zeros too.
        for (byte anInput : input) {
            if (anInput == 0)
                stringBuilder.insert(0, ALPHABET.charAt(0));
            else
                break;
        }

        return stringBuilder.toString();
    }

    /**
     * Base58로 엔코딩된 문자열을 받아 MoaBase58 디코딩한 바이트 배열을 반환한다.
     * @param input Base58로 엔코딩된 문자열 입력
     * @return byte[] Base58로 디코딩된 바이트 배열 반환
     */
    public static byte[] decode(String input)
    {
        byte[] bytes = decodeToBigInteger(input).toByteArray();

        boolean stripSignByte = bytes.length > 1 && bytes[0] == 0 && bytes[1] < 0;

        // Count the leading zeros, if any.
        int leadingZeros = 0;
        for (int i = 0; input.charAt(i) == ALPHABET.charAt(0); i++)
            leadingZeros++;

        // Now cut/pad correctly. Java 6 has a convenience for this, but Android can't use it.
        byte[] tmp = new byte[bytes.length - (stripSignByte ? 1 : 0) + leadingZeros];
        System.arraycopy(bytes, stripSignByte ? 1 : 0, tmp, leadingZeros, tmp.length - leadingZeros);

        return tmp;
    }

    private static BigInteger decodeToBigInteger(String input)
    {
        BigInteger bigInteger = BigInteger.valueOf(0);

        // Work backwards through the string.
        for (int i = input.length() - 1; i >= 0; i--) {
            int alphaIndex = ALPHABET.indexOf(input.charAt(i));
            if (alphaIndex == -1)
                throw new IllegalArgumentException("In MoaBase58.decodeToBigInteger(), Illegal character " + input.charAt(i) + " at index " + i + ". Throwing new IlleglArgumentException.");
            bigInteger = bigInteger.add(BigInteger.valueOf(alphaIndex).multiply(BASE.pow(input.length() - 1 - i)));
        }
        return bigInteger;
    }
}
