package com.demo.payments.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * FIXED (PCI DSS 6.4.1 / ISO A.8.29): standard response hardening headers that the
 * ZAP baseline scan checks for.
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
        res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        chain.doFilter(req, res);
    }
}
