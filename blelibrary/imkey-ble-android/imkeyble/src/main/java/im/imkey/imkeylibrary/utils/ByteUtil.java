package im.imkey.imkeylibrary.utils;

import java.util.Arrays;
import java.util.Locale;

import im.imkey.imkeylibrary.common.Messages;
import im.imkey.imkeylibrary.exception.ImkeyException;

public class ByteUtil {
    public static String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) {
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        }
        StringBuilder sb = new StringBuilder();
        int tmp;
        for (byte aByte : bytes) {
            tmp = aByte >= 0 ? aByte : 256 + aByte;
            if (tmp < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(tmp));
        }
        return sb.toString().toUpperCase(Locale.CHINA);
    }

    public static byte[] hexStringToByteArray(String str) {
        if (str == null || str.length() == 0 || (str.length() % 2) != 0) {
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        }
        int len = str.length() / 2;
        byte[] result = new byte[len];
        String tmp;
        for (int i = 0; i < len; i++) {
            tmp = str.substring(i * 2, (i + 1) * 2);
            try {
                result[i] = (byte) Integer.parseInt(tmp, 16);
            } catch (Exception e) {

                result[i] = 0x00;
            }
        }
        return result;
    }

    public static byte[] longToByteArray(long num) {
        byte[] result = new byte[8];
        result[0] = (byte) (num >>> 56);// 取最高8位放到0下标
        result[1] = (byte) (num >>> 48);// 取最高8位放到0下标
        result[2] = (byte) (num >>> 40);// 取最高8位放到0下标
        result[3] = (byte) (num >>> 32);// 取最高8位放到0下标
        result[4] = (byte) (num >>> 24);// 取最高8位放到0下标
        result[5] = (byte) (num >>> 16);// 取次高8为放到1下标
        result[6] = (byte) (num >>> 8); // 取次低8位放到2下标
        result[7] = (byte) (num); // 取最低8位放到3下标
        return result;
    }

    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] result = Arrays.copyOf(b1, b1.length + b2.length);
        System.arraycopy(b2, 0, result, b1.length, b2.length);
        return result;
    }

    private static byte[] trimLeadingBytes(byte[] bytes, byte b) {
        int offset = 0;
        for (; offset < bytes.length - 1; offset++) {
            if (bytes[offset] != b) {
                break;
            }
        }
        return Arrays.copyOfRange(bytes, offset, bytes.length);
    }

    public static byte[] trimLeadingZeroes(byte[] bytes) {
        return trimLeadingBytes(bytes, (byte) 0);
    }
}
