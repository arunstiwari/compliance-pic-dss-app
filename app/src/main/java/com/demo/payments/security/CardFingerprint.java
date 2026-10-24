package com.demo.payments.security;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class CardFingerprint {

    public String of(String pan) {
        try {
            // PLANTED ISSUE (PCI DSS 3.5.1 / ISO A.8.24): unkeyed MD5 of a PAN is
            // weak cryptography; PANs are brute-forceable from an unkeyed hash.
            MessageDigest md = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(md.digest(pan.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
