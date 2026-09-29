package com.santhosh.phishing.controller;

import com.santhosh.phishing.detection.DetectionResult;
import com.santhosh.phishing.service.ScanService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final ScanService scanService;
    public ApiController(ScanService scanService) { this.scanService = scanService; }

    @PostMapping("/scan")
    public DetectionResult scan(@RequestBody Map<String, String> body) {
        try {
            return scanService.scan(body.get("url"));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
        }
    }
}
