package com.santhosh.phishing.history;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    List<ScanHistory> findTop50ByOrderByScannedAtDesc();
}
