package com.demo.payments.config;

import org.springframework.context.annotation.Configuration;

/**
 * Settings for the (fictional) PayGate card processor.
 */
@Configuration
public class PaymentGatewayConfig {

    // PLANTED ISSUE (PCI DSS 8.6.2 / ISO A.5.17): live credential hard-coded in source.
    // "PayGate" is fictional, so this value is fake and safe to push; the demo's
    // .gitleaks.toml has a rule for its key format.
    private static final String API_KEY = "pgk_live_7Hq2mX9vLz4Rt1Yb6Nc3Hd5Wj0Ae8UsK";

    public String apiKey() {
        return API_KEY;
    }

    public String endpoint() {
        return "https://api.paygate.example/v2";
    }
}
