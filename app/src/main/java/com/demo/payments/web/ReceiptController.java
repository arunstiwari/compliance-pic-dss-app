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
        // PLANTED ISSUE (PCI DSS 6.2.4 / ISO A.8.28): the interpolator evaluates
        // ${script:...}, ${dns:...} and ${url:...} lookups from user input (Text4Shell pattern).
        String rendered = StringSubstitutor.createInterpolator().replace(template);
        return Map.of("receipt", rendered);
    }
}
