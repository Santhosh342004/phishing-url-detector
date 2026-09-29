package com.santhosh.phishing.history;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_history")
public class ScanHistory {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, length = 2048)
    private String url;
    private int riskScore;
    @Column(nullable = false)
    private String classification;
    @Column(nullable = false)
    private LocalDateTime scannedAt;

    protected ScanHistory() {}
    public ScanHistory(String url, int riskScore, String classification) {
        this.url = url; this.riskScore = riskScore; this.classification = classification;
        this.scannedAt = LocalDateTime.now();
    }
    public Long getId() { return id; }
    public String getUrl() { return url; }
    public int getRiskScore() { return riskScore; }
    public String getClassification() { return classification; }
    public LocalDateTime getScannedAt() { return scannedAt; }
}
