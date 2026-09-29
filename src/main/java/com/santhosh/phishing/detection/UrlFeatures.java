package com.santhosh.phishing.detection;

import java.util.List;

public record UrlFeatures(
        int length, boolean https, boolean ipHost, int subdomainCount,
        int suspiciousKeywordCount, int atSymbol, int hyphenInHost,
        List<String> findings) {}
