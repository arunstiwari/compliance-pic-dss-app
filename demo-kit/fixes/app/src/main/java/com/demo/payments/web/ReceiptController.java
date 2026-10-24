package com.demo.payments.web;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/receipts")
public class ReceiptController {

    /** Renders a merchant-supplied receipt template, e.g. "Thanks for paying ${amount}". */
    @PostMapping("/preview")
    public Map<String, String> preview(@RequestBody Map<String, String> body) {
        String template = body.getOrDefault("template", "");
        // FIXED (PCI DSS 6.2.4 / ISO A.8.28): only an explicit allow-list of variables
        // is substituted; no script/dns/url lookups.
        Map<String, String> vars = Map.of(
                "amount", body.getOrDefault("amount", ""),
                "merchant", body.getOrDefault("merchant", ""));
        return Map.of("receipt", new StringSubstitutor(vars).replace(template));
    }
}
