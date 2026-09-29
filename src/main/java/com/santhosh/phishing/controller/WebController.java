package com.santhosh.phishing.controller;

import com.santhosh.phishing.detection.DetectionResult;
import com.santhosh.phishing.history.ScanHistory;
import com.santhosh.phishing.service.ScanService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.List;

@Controller
public class WebController {
    private final ScanService scanService;
    public WebController(ScanService scanService) { this.scanService = scanService; }

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("history", scanService.history());
        return "index";
    }

    @PostMapping("/scan")
    public String scan(@RequestParam String url, Model model) {
        try {
            DetectionResult result = scanService.scan(url);
            model.addAttribute("result", result);
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
        }
        model.addAttribute("history", scanService.history());
        return "index";
    }
}
