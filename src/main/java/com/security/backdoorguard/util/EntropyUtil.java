package com.security.backdoorguard.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Tinh Shannon entropy cua mot chuoi - dung de phat hien chuoi "trong giong ngau nhien"
 * (mat khau bi mat, chuoi base64 encode payload...) thay vi ngon ngu tu nhien binh thuong.
 * Van ban tieng nguoi thong thuong co entropy ~3.0-4.0 bit/ky tu; chuoi ngau nhien/base64
 * thuong tren 4.0-4.5 bit/ky tu.
 */
public final class EntropyUtil {

    private EntropyUtil() {}

    public static double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        double entropy = 0;
        int len = s.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
