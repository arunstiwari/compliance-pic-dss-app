package com.demo.payments.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Settings for the (fictional) PayGate card processor.
 */
@Configuration
public class PaymentGatewayConfig {

    // FIXED (PCI DSS 8.6.2 / ISO A.5.17): injected at runtime from the environment
    // (in production, from a secrets manager such as AWS Secrets Manager or Vault).
    private final String apiKey;

    public PaymentGatewayConfig(@Value("${paygate.api-key:}") String apiKey) {
        this.apiKey = apiKey;
    }

    public String apiKey() {
        return apiKey;
    }

    public String endpoint() {
        return "https://api.paygate.example/v2";
    }
}
