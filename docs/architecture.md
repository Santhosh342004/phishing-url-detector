# Architecture

Browser → Thymeleaf web controller / JSON API → ScanService → UrlAnalyzer → ScanHistoryRepository → H2 database.

The detection engine is a Spring-managed component but contains plain Java analysis logic, allowing it to be unit-tested independently. Submitted URLs are parsed as text and are not fetched.
