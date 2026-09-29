# PhishGuard — Phishing URL Detector

A Java and Spring Boot educational application that inspects URL text for common phishing indicators, calculates a heuristic risk score, and stores scan history.

## Features
- URL validation and normalization
- Rule-based URL feature analysis
- Heuristic risk score with findings
- Web interface built with Thymeleaf, Bootstrap and CSS
- Recent scan history stored with Spring Data JPA
- JSON endpoint: `POST /api/scan`
- Unit tests with JUnit 5

## Technology
Java 21, Maven, Spring Boot 3, Spring MVC, Thymeleaf, Spring Data JPA, H2, JUnit 5.

## Run locally
1. Install JDK 21 and Maven (or use Eclipse's embedded Maven).
2. Import this directory into Eclipse: **File → Import → Maven → Existing Maven Projects**.
3. Select the project folder and finish import.
4. Run `PhishingDetectorApplication.java` as **Java Application**, or execute:
   ```bash
   mvn spring-boot:run
   ```
5. Open http://localhost:8080.

The default database is a local H2 file database created in `./data`. No external database setup is required for the starter version.

## API
`POST /api/scan`
```json
{"url":"https://example.com"}
```
Returns the normalized URL, risk score, classification, extracted features and explanation.

## Tests
```bash
mvn test
```

## Deployment
Build with `mvn clean package` and deploy the generated JAR to a Java 17-compatible hosting service. Configure `PORT` if required by the platform. For a production deployment, configure a managed database, secure secrets, HTTPS, rate limiting, and suitable retention policies.

## Important limitations
This is a rule-based educational detector, not a machine-learning model, threat-intelligence service, browser protection product, or definitive safety check. URL features can produce false positives and false negatives. HTTPS does not establish trustworthiness. The app analyzes URL text and does not fetch or open submitted URLs. Do not use its output as the sole basis for security decisions.
