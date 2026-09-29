
package com.santhosh.phishing.detection;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
public class UrlAnalyzer {

    private static final Set<String> KEYWORDS = Set.of(
            "login",
            "verify",
            "update",
            "banking",
            "password",
            "signin",
            "account",
            "wallet",
            "confirm",
            "secure"
    );

    public DetectionResult analyze(String input) {

        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Please enter a URL.");
        }

        String raw = input.trim();

        String candidate = raw.matches("(?i)^https?://.*")
                ? raw
                : "https://" + raw;

        final URI uri;

        try {
            uri = new URI(candidate);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException(
                    "The URL format is invalid."
            );
        }

        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException(
                    "Enter a valid URL with a domain or IP address."
            );
        }

        host = host.toLowerCase(Locale.ROOT);
        String lower = candidate.toLowerCase(Locale.ROOT);

        // Basic URL features
        boolean https = "https".equalsIgnoreCase(uri.getScheme());

        boolean ipHost = isIpv4(host);

        int subdomains = Math.max(
                0, host.split("\\.").length - 2
        );

        int keywordCount = (int) KEYWORDS.stream()
                .filter(lower::contains)
                .count();

        int atSymbol = count(raw, '@');

        int hyphenInHost = count(host, '-');

        // Risk scoring
        int score = 0;

        List<String> findings = new ArrayList<>();

        if (raw.length() > 75) {
            score += 15;
            findings.add("Unusually long URL");
        }

        if (keywordCount > 0) {
            score += Math.min(20, keywordCount * 15);
            findings.add(
                    "Contains login/account-related keyword(s)"
            );
        }

        if (ipHost) {
            score += 30;
            findings.add(
                    "Uses an IPv4 address as the host"
            );
        }

        if (subdomains > 2) {
            score += 15;
            findings.add(
                    "Contains many subdomain levels"
            );
        }

        if (atSymbol > 0) {
            score += 20;
            findings.add(
                    "Contains an @ symbol, which can obscure URL interpretation"
            );
        }

        if (hyphenInHost > 2) {
            score += 10;
            findings.add(
                    "Host contains several hyphens"
            );
        }

        if (!https) {
            score += 5;
            findings.add(
                    "Uses HTTP rather than HTTPS"
            );
        }

        // Keep score within 0-100
        score = Math.min(100, score);

        // Classification
        String classification;

        if (score >= 50) {
            classification = "High suspicion";
        } else if (score >= 20) {
            classification = "Caution";
        } else {
            classification = "Few indicators detected";
        }

        // Explanation
        String explanation;

        if (findings.isEmpty()) {
            explanation =
                    "No configured suspicious indicators were detected. "
                    + "This does not prove the site is safe.";
        } else {
            explanation =
                    "One or more configured indicators were detected. "
                    + "Verify the domain independently; this score "
                    + "is heuristic, not a probability.";
        }

        // Build feature result
        UrlFeatures features = new UrlFeatures(
                raw.length(),
                https,
                ipHost,
                subdomains,
                keywordCount,
                atSymbol,
                hyphenInHost,
                List.copyOf(findings)
        );

        return new DetectionResult(
                candidate,
                score,
                classification,
                features,
                explanation
        );
    }

    // Validate IPv4 address
    private static boolean isIpv4(String host) {

        if (host == null) {
            return false;
        }

        String[] parts = host.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        try {
            for (String part : parts) {

                if (part.isEmpty()) {
                    return false;
                }

                int octet = Integer.parseInt(part);

                if (octet < 0 || octet > 255) {
                    return false;
                }
            }

            return true;

        } catch (NumberFormatException ex) {
            return false;
        }
    }

    // Count occurrences of a character
    private static int count(String value, char target) {

        int total = 0;

        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == target) {
                total++;
            }
        }

        return total;
    }
}