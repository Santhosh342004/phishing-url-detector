package com.santhosh.phishing.detection;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UrlAnalyzerTest {
    private final UrlAnalyzer analyzer = new UrlAnalyzer();

    @Test void acceptsOrdinaryHttpsUrl() {
        DetectionResult result = analyzer.analyze("https://example.com");
        assertEquals("https://example.com", result.normalizedUrl());
        assertEquals(0, result.riskScore());
    }

    @Test void flagsIpHostAndKeyword() {
        DetectionResult result = analyzer.analyze("http://192.168.1.10/login");
        assertTrue(result.features().ipHost());
        assertTrue(result.features().suspiciousKeywordCount() > 0);
        assertTrue(result.riskScore() >= 50);
    }

    @Test void rejectsBlankInput() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.analyze(" "));
    }
}
