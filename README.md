# QRShield

## Explainable Phishing Detection for QR-Based Campus Scams

QRShield is a defensive cybersecurity prototype designed to analyze URLs embedded in QR codes before users interact with the destination.

The project focuses on QR-based social engineering, where the actual destination URL is hidden behind a QR code and users may scan it without being able to visually inspect the link beforehand.

QRShield combines QR-code decoding with explainable URL intelligence to identify suspicious characteristics and present them as a human-readable security assessment.

---

## Problem

QR codes are increasingly used for registrations, notices, payments, authentication, and online services.

A malicious QR code can redirect users toward a phishing or fraudulent destination. Because the URL is hidden inside the QR code, users may not recognize suspicious characteristics before opening it.

This creates an opportunity for social engineering attacks in campuses, public spaces, advertisements, and other environments where QR codes are trusted.

---

## Solution

QRShield provides a local analysis pipeline that:

1. Accepts a URL or QR-code image.
2. Extracts the destination URL from the QR code.
3. Normalizes and analyzes the URL.
4. Examines multiple structural and lexical characteristics.
5. Calculates an explainable heuristic risk score.
6. Identifies the indicators contributing to the assessment.
7. Presents a human-readable security recommendation.

The goal is not simply to produce a number, but to explain **why a URL received a particular risk assessment.**

---

## Current Detection Capabilities

### URL Intelligence

QRShield currently analyzes characteristics including:

- HTTPS usage
- IP-address destinations
- URL length
- Hostname length
- Number of subdomains
- URL path depth
- Query-parameter count
- URL fragments
- `@` symbol usage
- Percent-encoded characters
- Decoded URL differences
- Suspicious keywords
- Hyphen-heavy hostnames
- Digit-heavy hostnames
- Suspicious-looking Top-Level Domains (TLDs)
- Hostname entropy

These indicators are combined using heuristic rules to produce an explainable risk assessment.

---

## Explainable Findings

Instead of displaying only a risk score, QRShield records the characteristics that contributed to the assessment.

Example categories include:

- **LOW** — indicator requiring little or no additional concern
- **MEDIUM** — characteristic requiring additional verification
- **HIGH** — stronger suspicious characteristic

The exact assessment depends on the combination of indicators detected by the current heuristic engine.

---

## Risk Levels

### LOW RISK
No obvious suspicious indicators were detected by the current rules. This does **not** guarantee that the destination is safe.

### CAUTION
One or more characteristics require additional verification before interacting with the destination.

### HIGH RISK
Multiple suspicious characteristics were detected by the current heuristic rules. A high-risk result is an indication for caution, not proof that a website is malicious.

---

## Detection Pipeline

```text
                QR Code Image
                     │
                     ▼
                QR Decoder
                     │
                     ▼
               Extracted URL
                     │
                     ▼
              URL Normalization
                     │
                     ▼
            URL Intelligence Engine
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
    URL Characteristics    Suspicious Indicators
          │                     │
          └──────────┬──────────┘
                     ▼
              Heuristic Rules
                     │
                     ▼
                 Risk Score
                     │
                     ▼
             Explainable Findings
                     │
                     ▼
           Security Recommendation



Example Use Case
A campus user receives a QR code claiming to provide an urgent university account verification or scholarship service.

Instead of immediately scanning and visiting the destination, the QR code can be submitted to QRShield for analysis.

QRShield extracts the URL and examines characteristics such as:

HTTP instead of HTTPS

Long URL

Suspicious keywords

Deep URL path

Unusual hostname structure

Suspicious-looking TLD

The application then presents the detected indicators alongside the risk assessment, allowing the user to understand what triggered the warning.

Technology Stack
Python — Analysis engine and application logic

Flask — Local web application framework

OpenCV — QR-code detection and decoding

HTML5 & CSS3 — Interface presentation and styling

Git — Version control

PROJECT STRUCTURE

qrshield/
│
├── app.py
├── analyzer.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
├── demo_qr/
│   ├── safe_qr.png
│   ├── suspicious_qr.png
│   └── campus_phishing_demo.png
│
├── uploads/
│
├── .gitignore
└── README.md