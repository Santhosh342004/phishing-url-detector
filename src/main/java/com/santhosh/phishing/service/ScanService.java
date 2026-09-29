package com.santhosh.phishing.service;

import com.santhosh.phishing.detection.DetectionResult;
import com.santhosh.phishing.detection.UrlAnalyzer;
import com.santhosh.phishing.history.ScanHistory;
import com.santhosh.phishing.history.ScanHistoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
public class ScanService {
    private final UrlAnalyzer analyzer;
    private final ScanHistoryRepository repository;
    public ScanService(UrlAnalyzer analyzer, ScanHistoryRepository repository) {
        this.analyzer = analyzer; this.repository = repository;
    }
    @Transactional
    public DetectionResult scan(String url) {
        DetectionResult result = analyzer.analyze(url);
        repository.save(new ScanHistory(result.normalizedUrl(), result.riskScore(), result.classification()));
        return result;
    }
    @Transactional(readOnly = true)
    public List<ScanHistory> history() { return repository.findTop50ByOrderByScannedAtDesc(); }
}
