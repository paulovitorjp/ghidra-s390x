// ZosUtil.java -- shared parsing helpers for the z/OS loaders.
// EBCDIC (Cp037) name decoding and big-endian readers.
package s390x.loaders;

import java.nio.charset.Charset;

public class ZosUtil {

    public static final Charset CP037 = Charset.forName("Cp037");

    /** Decode an EBCDIC blank-padded name field, trimming trailing blanks. */
    public static String ebcdicName(byte[] buf, int off, int len) {
        String s = new String(buf, off, len, CP037);
        int end = s.length();
        while (end > 0 && (s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\0')) {
            end--;
        }
        return s.substring(0, end);
    }

    public static int u16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    public static int u24(byte[] b, int off) {
        return ((b[off] & 0xff) << 16) | ((b[off + 1] & 0xff) << 8) | (b[off + 2] & 0xff);
    }

    public static long u32(byte[] b, int off) {
        return ((long) (b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) |
               ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    /** Make a string safe for use as a Ghidra memory-block / symbol name. */
    public static String sanitize(String name, String fallback) {
        if (name == null || name.isEmpty()) {
            return fallback;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '#') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        String s = sb.toString();
        return s.isEmpty() ? fallback : s;
    }

    /** Parse a hex ("0x...") or decimal image-base option value. */
    public static long parseBase(String s, long dflt) {
        if (s == null) {
            return dflt;
        }
        s = s.trim();
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return Long.parseLong(s.substring(2), 16);
            }
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return dflt;
        }
    }
}
