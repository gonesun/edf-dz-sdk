package com.ttk.dz.openapi.sdk;

import java.util.List;

/**
 * 字符串工具类
 *
 */
public final class DzStringUtil {

    public static boolean isNullOrEmpty(String str) {
        if (str == null) {
            return true;
        }
        return str.isEmpty();
    }

    public static String join(List<String> elements, String seperator) {
        if (elements == null || elements.isEmpty()) {
            return null;
        }

        if (seperator == null) {
            seperator = "";
        }
        StringBuilder sb = new StringBuilder();
        int length = elements.size();
        for (int index = 0; index < length; index++) {
            if (index > 0) {
                sb.append(seperator);
            }
            sb.append(elements.get(index));
        }
        return sb.toString();
    }

}
