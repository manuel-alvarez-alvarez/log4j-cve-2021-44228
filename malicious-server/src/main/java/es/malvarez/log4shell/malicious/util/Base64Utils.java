package es.malvarez.log4shell.malicious.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public abstract class Base64Utils {

    private Base64Utils() {

    }

    public static String toBase64(final String data) {
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String fromBase64(final String data) {
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);

    }
}
