# Crucible: Multi-Engine Web Vulnerability Scanner

Crucible is a modular Dynamic Application Security Testing (DAST) framework designed to identify and audit web-based vulnerabilities. Developed with a focus on automation, it integrates a web crawler with specialized injection engines and a centralized Flask-based management dashboard.

---

## Core Features

- **Automated Discovery**  
  Implements a Breadth-First Search (BFS) crawler to map target domains and identify attack surfaces such as HTML forms and URL parameters.

- **SQL Injection Engine**  
  A dedicated module for detecting SQL injection vulnerabilities using tautologies, error-based, and union-based payload vectors.

- **Centralized Reporting**  
  A professional web dashboard built with Flask for real-time monitoring and structured vulnerability reporting.

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

 1. Repository Setup

```bash
git clone https://github.com/RitabrataDutta01/Crucible.git
cd crucible
```
2. Environment Configuration
```bash
uv venv
# Windows:
.venv\Scripts\activate

# Linux / Mac:
source .venv/bin/activate

uv sync
```
3. Dependencies
```bash 
uv add flask requests beautifulsoup4 lxml python-dotenv
```

### Usage

1. Launch the application:
```bash
uv run python app.py
```
    
2. Access the dashboard at http://127.0.0.1:5000.

3. Input the target URL for scanning.

4. Review the generated vulnerability table for identified endpoints and payloads.

### Project Structure

```text
crucible/
├── app.py              # Application entry point and Flask routing
├── packages/           # Modular vulnerability engines
│   ├── crawler.py      # Web crawling and form extraction logic
│   └── sqli.py         # SQL injection detection module
├── static/             # Frontend assets (CSS and JavaScript)
├── templates/          # Jinja2 HTML templates
├── data/               # Security payloads and JSON data
└── pyproject.toml      # Dependency and project metadata
```

### Disclaimer

Crucible is intended for educational purposes and authorized penetration testing only. Unauthorized use of this tool against systems without explicit permission is illegal. The developer assumes no liability for misuse.

### Author

Ritabrata Dutta
Second-year B.Tech Student, Computer Science & Engineering
Adamas University, West Bengal, India