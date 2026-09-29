package com.santhosh.phishing.detection;

public record DetectionResult(String normalizedUrl, int riskScore, String classification,
                              UrlFeatures features, String explanation) {}
