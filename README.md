<div align="center">

# 🔥 Crucible

### Intelligent Web Vulnerability Assessment & Security Auditing Framework

<img src="assets/welcome-dash.png" width="850">

<br>

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Framework-Flask-black?style=for-the-badge&logo=flask">
<img src="https://img.shields.io/badge/Domain-Web%20Security-red?style=for-the-badge">
<img src="https://img.shields.io/badge/AI-Gemini-purple?style=for-the-badge">
</p>

</div>


# 📖 Overview

**Crucible** is an automated web vulnerability assessment framework designed to assist security researchers, students, and penetration testers in identifying and understanding common web application vulnerabilities.

The framework combines:

- Automated reconnaissance
- Web application crawling
- Payload-driven vulnerability testing
- Concurrent security analysis
- Automated reporting
- AI-assisted vulnerability explanation


Crucible follows a modular architecture where each component performs a specific responsibility in the security assessment workflow, allowing the framework to remain maintainable, scalable, and easy to extend.


---

# ✨ Features


## 🌐 Automated Web Reconnaissance

Crucible begins an assessment by mapping the target application's attack surface.

The crawler identifies:

- Internal webpages
- Available endpoints
- HTML forms
- Input parameters
- HTTP request methods
- Authenticated application routes


This information is then passed to vulnerability analysis modules for further testing.


---

# 🛡️ Vulnerability Assessment Modules


## 💉 SQL Injection Scanner

**Module:**

```
packages/sqli.py
```

The SQL injection engine evaluates discovered input parameters for database-related vulnerabilities.

### Detection Capabilities

- Authentication bypass SQL injection
- Error-based SQL injection
- Time-based blind SQL injection
- Response behaviour comparison
- Database error signature analysis
- Timing-based verification


The module uses external payload databases, allowing security testing patterns to be updated without modifying the core scanning logic.


---

## 🕷️ Cross-Site Scripting Scanner

**Module:**

```
packages/XSS.py
```

The XSS engine identifies unsafe handling of user-controlled input that may result in client-side script execution.

### Detection Capabilities

- Reflected XSS detection
- Blind XSS testing
- HTML context analysis
- Attribute injection analysis
- JavaScript context analysis
- Payload reflection verification


The scanner analyses how input is reflected by the application and determines whether proper output handling mechanisms are implemented.


---

# 🤖 AI-Powered Security Analysis

Crucible integrates Google's Gemini AI to provide deeper explanations of discovered vulnerabilities.

The AI analysis system provides:

- Vulnerability explanations
- Impact analysis
- Payload behaviour explanation
- Recommended security fixes
- Secure coding guidance


Example:

```
Finding:
Reflected XSS

Impact:
Attacker-controlled JavaScript execution

Recommendation:
Implement context-aware output encoding
and proper input validation.
```


---

# 🏗️ Architecture Overview


```
                         User
                          |
                          |
                  Flask Dashboard
                          |
                          |
                       app.py
                          |
                          |
              Authentication Management
                          |
                          |
                    crawler.py
                          |
                          |
             Attack Surface Discovery
                          |
              ---------------------
              |                   |
              ↓                   ↓
           sqli.py             XSS.py
              |
              |
     Vulnerability Findings
              |
              |
       Report Generation
              |
              |
        Gemini AI Analysis
```


---

# 📂 Project Structure


```
Crucible/

│
├── app.py
│   └── Main Flask application controller
│
├── forge.py
│   └── Application launcher/helper utilities
│
├── config.py
│   └── Configuration management
│
├── packages/
│
│   ├── crawler.py
│   │   └── Web discovery and endpoint extraction
│   │
│   ├── sqli.py
│   │   └── SQL Injection detection engine
│   │
│   └── XSS.py
│       └── Cross-Site Scripting detection engine
│
├── data/
│   └── Security payload databases and signatures
│
├── templates/
│   └── Flask HTML templates
│
├── static/
│   └── CSS and JavaScript resources
│
├── reports/
│   └── Generated vulnerability reports
│
└── assets/
    └── Documentation images
```


---

# 🧩 System Architecture & Module Overview

Crucible follows a modular security assessment architecture where every component is responsible for a dedicated stage of the vulnerability analysis workflow.

This separation improves:

- Maintainability
- Scalability
- Debugging
- Future feature expansion


---

# Core Application Layer


## `app.py` — Application Controller

The `app.py` module acts as the central orchestration layer of Crucible.

It connects the dashboard, authentication system, crawler, vulnerability scanners, reporting system, and AI analysis engine.

### Responsibilities

- Initializes the Flask application
- Handles dashboard requests
- Accepts target information
- Creates authenticated sessions
- Coordinates security scans
- Collects vulnerability findings
- Generates reports
- Sends findings to Gemini AI


---

# Discovery Layer


## `crawler.py` — Web Application Discovery Engine

The crawler performs the reconnaissance stage of the security assessment.

Its purpose is to discover possible attack surfaces before vulnerability testing begins.


### Capabilities

- Website crawling
- Internal endpoint discovery
- Form extraction
- Parameter identification
- HTTP method detection
- Authenticated crawling


### Workflow

```
Target Application

        ↓

Crawler

        ↓

Discovered URLs + Forms + Parameters

        ↓

Security Testing Modules
```


---

# Vulnerability Analysis Layer


## `sqli.py` — SQL Injection Assessment Engine

The SQL injection module analyses discovered parameters for database vulnerabilities.


### Responsibilities

- Inject SQL payloads
- Compare application responses
- Detect database error behaviour
- Analyse response delays
- Verify potential vulnerabilities


---

## `XSS.py` — Cross-Site Scripting Analysis Engine

The XSS module analyses whether user-controlled input can execute unsafe client-side code.


### Responsibilities

- Generate XSS payloads
- Analyse reflection behaviour
- Identify injection contexts
- Verify potential execution paths


---

# Configuration Layer


## `config.py`

The configuration module manages application settings and environment-based values.


### Responsibilities

- API configuration
- Runtime settings
- Scanner parameters
- Environment management


---

# Data Layer


## `data/`

The data directory stores external security intelligence used by Crucible.

Contains:

- SQL injection payload collections
- XSS payload libraries
- Error signatures
- Security testing datasets


Keeping security data separate from application logic allows payloads and signatures to evolve independently.


---

# Presentation Layer


## `templates/`

Contains Flask HTML templates used to build the dashboard interface.

Provides:

- Scan configuration pages
- Results display
- User interaction components


---

## `static/`

Contains frontend resources.

Includes:

- CSS styling
- JavaScript functionality
- Dashboard assets


---

# 🔄 Complete Scan Workflow


```
1. User enters target application

              ↓

2. Authentication setup

              ↓

3. Website crawling

              ↓

4. Endpoint discovery

              ↓

5. SQL Injection analysis

              ↓

6. XSS vulnerability analysis

              ↓

7. Findings collection

              ↓

8. Report generation

              ↓

9. Gemini AI security explanation
```


---

# ⚙️ Installation


## Clone Repository

```bash
git clone https://github.com/RitabrataDutta01/Crucible.git

cd Crucible
```


## Install Dependencies

```bash
pip install -r requirements.txt
```


---

# 🔑 Environment Configuration


Crucible requires a Gemini API key for AI-powered vulnerability analysis.


### Linux

```bash
export GOOGLE_API_KEY="your_api_key"
```


### Windows

```powershell
setx GOOGLE_API_KEY "your_api_key"
```


---

# ▶️ Running Crucible


Start the application:

```bash
python app.py
```


Open the dashboard:

```
http://localhost:5000
```


---

# 📸 Screenshots


## Dashboard

<img src="assets/welcome-dash.png">


## Scan Progress

<img src="assets/ongoing.png">


## Results Dashboard

<img src="assets/results-dash.png">


---

# 🛠️ Technology Stack


| Technology | Purpose |
|---|---|
| Python | Core development language |
| Flask | Web application framework |
| BeautifulSoup | HTML parsing |
| Requests | HTTP communication |
| ThreadPoolExecutor | Concurrent scanning |
| Gemini AI | Vulnerability explanation |
| JSON | Payload storage |
| HTML/CSS/JS | Dashboard interface |


---

# 🚀 Future Improvements


- [ ] CVSS vulnerability scoring
- [ ] PDF security reports
- [ ] OWASP Top 10 expansion
- [ ] Improved vulnerability verification
- [ ] Plugin-based scanner architecture
- [ ] API security testing
- [ ] Advanced authentication support


---

# ⚠️ Disclaimer


Crucible is intended for:

✅ Educational purposes  
✅ Authorized penetration testing  
✅ Security research  


Only scan applications that you have explicit permission to test.

The author is not responsible for misuse of this software.


---

# 👨‍💻 Author


## Ritabrata Dutta

Cybersecurity & Software Development Enthusiast


⭐ If you find Crucible useful, consider starring the repository.