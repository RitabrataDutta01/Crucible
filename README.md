# Crucible: Multi-Engine Web Vulnerability Scanner

Crucible is a modular Dynamic Application Security Testing (DAST) framework designed to identify and audit web-based vulnerabilities. Developed with a focus on automation, it integrates a web crawler with specialized injection engines and a centralized Flask-based management dashboard.

![Python](https://img.shields.io/badge/Python-3.10.19-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Core Features

- **Automated Discovery**  
  Implements a Breadth-First Search (BFS) crawler to map target domains and identify attack surfaces such as HTML forms and URL parameters.

- **SQL Injection Engine**  
  Detects SQL injection vulnerabilities across multiple vectors: authentication bypass, error-based signature detection, and time-based blind injection.

- **Cross-Site Scripting Engine**  
  Identifies reflected XSS vulnerabilities by testing whether injected payloads are returned unescaped in server responses.

- **Centralized Reporting**  
  A web dashboard built with Flask for real-time scan monitoring, structured vulnerability output, and persistent JSON report history.

- **Modern Development Stack**  
  Managed via the `uv` package manager for high-performance dependency handling and environment isolation.

---

## Technical Stack

- **Backend:** Python 3.10.19, Flask
- **Package Management:** uv
- **Scanning Engine:** lxml, BeautifulSoup4
- **Frontend:** HTML5, CSS3 (Dark Theme), JavaScript
- **Environment:** Developed on ASUS TUF F17, compatible with Windows and Linux/WSL environments

---

## Installation

This project requires **Python 3.10.19** and the **uv package manager**.

**1. Repository Setup**
```bash
git clone https://github.com/RitabrataDutta01/Crucible.git
cd crucible
```

**2. Environment Configuration**
```bash
uv venv

# Windows:
.venv\Scripts\activate

# Linux / macOS:
source .venv/bin/activate

uv sync
```

**3. Dependencies**
```bash
uv add flask requests beautifulsoup4 lxml python-dotenv
```

---

## Usage

1. Launch the application:
    ```bash
    uv run python app.py
    ```
2. Access the dashboard at `http://127.0.0.1:5000`.
3. Input the target URL and initiate a scan.
4. Review the generated vulnerability table for identified endpoints, payloads, and evidence.

---

## Project Structure

```text
crucible/
├── app.py              # Application entry point and Flask routing
├── packages/           # Modular vulnerability engines
│   ├── crawler.py      # Web crawling and form extraction logic
│   ├── sqli.py         # SQL injection detection module
│   └── XSS.py          # Reflected XSS detection module
├── static/             # Frontend assets (CSS and JavaScript)
├── templates/          # Jinja2 HTML templates
├── data/               # Security payloads and signature data
├── reports/            # JSON logs of completed scans
└── pyproject.toml      # Dependency and project metadata
```

---

## Finding Schema

Every finding produced by the injection engines conforms to a unified schema to ensure consistent rendering across the dashboard and report files:

```json
{
  "vulnerability type": "Reflected XSS",
  "url":      "http://target.com/page",
  "payload":  "<script>alert(1)</script>",
  "severity": "High",
  "evidence": "Payload reflected verbatim in response from http://target.com/search",
  "endpoint": "http://target.com/search",
  "method":   "GET"
}
```

---

## Safe Test Targets

> Only scan applications you own or have explicit written permission to test.

| Target | URL |
|---|---|
| Altoro Mutual (IBM) | `http://demo.testfire.net` |
| VulnWeb | `http://testphp.vulnweb.com` |

---

## Ongoing Development

The following modules are currently in development as part of the Crucible expansion roadmap:

- **Local File Inclusion (LFI) Engine** — auditing URL parameters for directory traversal and sensitive file access.
- **Header Security Auditor** — analysis of HTTP response headers for security misconfigurations (CSP, HSTS, X-Frame-Options).
- **Machine Learning Integration** — implementation of a Naive Bayes classifier to improve detection accuracy and reduce false positives.

---

## Disclaimer

Crucible is intended for educational purposes and authorized penetration testing only. Unauthorized use of this tool against systems without explicit permission is illegal. The developer assumes no liability for misuse.

---

## Author

**Ritabrata Dutta**  
Second-year B.Tech Student, Computer Science & Engineering  
Adamas University, West Bengal, India