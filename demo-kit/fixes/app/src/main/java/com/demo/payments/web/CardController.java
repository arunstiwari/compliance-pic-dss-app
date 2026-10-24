package com.demo.payments.web;

import com.demo.payments.security.CardFingerprint;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/cards")
public class CardController {

    private final JdbcTemplate jdbc;
    private final CardFingerprint fingerprint;

    public CardController(JdbcTemplate jdbc, CardFingerprint fingerprint) {
        this.jdbc = jdbc;
        this.fingerprint = fingerprint;
    }

    /** Lists stored (tokenised) cards for a customer. */
    @GetMapping
    public List<Map<String, Object>> byCustomer(@RequestParam String customerId) {
        // FIXED (PCI DSS 6.2.4 / ISO A.8.28): bind variable, never string concatenation.
        return jdbc.queryForList(
                "SELECT id, customer_id, brand, last4 FROM cards WHERE customer_id = ?", customerId);
    }

    /** Returns a duplicate-detection fingerprint for a PAN without storing the PAN. */
    @PostMapping("/fingerprint")
    public Map<String, String> fingerprint(@RequestBody Map<String, String> body) {
        String pan = body.getOrDefault("pan", "");
        return Map.of("fingerprint", fingerprint.of(pan),
                      "last4", pan.length() >= 4 ? pan.substring(pan.length() - 4) : "");
    }
}
