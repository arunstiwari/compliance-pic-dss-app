package com.demo.payments.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

@Component
public class CardFingerprint {

    private final byte[] key;

    public CardFingerprint(@Value("${card.fingerprint-key:}") String key) {
        this.key = key.getBytes(StandardCharsets.UTF_8);
    }

    public String of(String pan) {
        if (key.length < 32) {
            throw new IllegalStateException("CARD_FINGERPRINT_KEY must be set (>= 32 bytes)");
        }
        try {
            // FIXED (PCI DSS 3.5.1 / ISO A.8.24): keyed HMAC-SHA256, key held outside the code.
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(pan.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
