# 🦅 VulnHawk — Async Web Vulnerability Scanner

> **Point it at a website. Get a security report in 60 seconds.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![asyncio](https://img.shields.io/badge/async-httpx-009688)](https://www.python-httpx.org)
[![FastAPI](https://img.shields.io/badge/Dashboard-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> ⚠️ **Legal Disclaimer:** Only scan targets you **own or have explicit written permission to test**. Unauthorized scanning is illegal. Use the provided Docker targets for testing.

---

## 🎬 Demo

```bash
$ vulnhawk scan http://localhost:3000 --depth 2

 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝

[1/8] Crawling target...       ████████████████ 47 URLs · 12 forms
[2/8] XSS Scanner...           ████████████████ 3 found
[3/8] SQLi Scanner...          ████████████████ 1 found
[4/8] Headers Scanner...       ████████████████ 5 issues
[5/8] CSRF Scanner...          ████████████████ 2 found
[6/8] Directory Scanner...     ████████████████ 2 exposed
[7/8] SSL/TLS Scanner...       ████████████████ 0 issues
[8/8] Cookie Scanner...        ████████████████ 3 issues

┌──────────┬───────┬────────────────────────────────────────┐
│ Severity │ Count │ Top Finding                            │
├──────────┼───────┼────────────────────────────────────────┤
│ CRITICAL │   1   │ SQL Injection — /login (POST)          │
│ HIGH     │   3   │ Reflected XSS — /search?q=             │
│ MEDIUM   │   4   │ Missing CSP · CSRF on 2 forms          │
│ LOW      │   5   │ Cookie flags · HSTS missing            │
│ INFO     │   4   │ Server version disclosed               │
└──────────┴───────┴────────────────────────────────────────┘
📄 Report: ./reports/localhost_20260622_143012.html
```

---

## ✨ Scanner Modules (8 Plugins)

| Scanner | Detects | Severity | CVSS Range |
|---------|---------|----------|------------|
| 🔴 **XSS** | Reflected Cross-Site Scripting in params & forms | HIGH | 6.1–7.2 |
| 🔴 **SQLi** | Error-based, boolean, time-based injection | CRITICAL | 8.1–9.8 |
| 🟠 **CSRF** | Missing anti-CSRF tokens on POST forms | MEDIUM | 6.5 |
| 🟡 **Headers** | Missing CSP, HSTS, X-Frame-Options, etc. | MEDIUM | 2.0–6.1 |
| 🟡 **Open Redirect** | Unvalidated URL redirections | MEDIUM | 6.1 |
| 🔵 **Directory Enum** | Exposed `.git`, `.env`, `/admin`, backups | CRITICAL–INFO | 2.0–9.1 |
| 🔵 **Cookie Flags** | Missing HttpOnly, Secure, SameSite | LOW | 3.1–4.3 |
| 🟢 **SSL/TLS** | Cert expiry, weak protocols, weak ciphers | HIGH–MEDIUM | 5.3–7.5 |
| 🟣 **Subdomain Enum** | Live subdomains via DNS + HTTP probe | MEDIUM–INFO | 2.0–5.3 |

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/yourusername/vulnhawk.git
cd vulnhawk

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux

pip install -e .
```

### CLI Usage

```bash
# Basic scan (depth 2 by default)
vulnhawk scan https://target.com

# Deeper scan with more threads
vulnhawk scan https://target.com --depth 3 --threads 20

# Save report to custom path
vulnhawk scan https://target.com --output ./my_report.html

# JSON output instead of HTML
vulnhawk scan https://target.com --format json
```

### Web Dashboard

```bash
python -m web.app
# → http://localhost:8080
```

### Docker (Full Stack)

```bash
# Start the vulnerable test app
docker run -d -p 3000:3000 bkimminich/juice-shop

# Scan it via CLI
vulnhawk scan http://localhost:3000 --depth 2

# Or scan via web dashboard
python -m web.app  # → http://localhost:8080
```

---

## 🏗️ Architecture

```
Target URL
    │
    ▼
┌──────────────┐
│    Crawler   │  async httpx · discovers URLs, forms, params, headers
│  (depth 1-5) │
└──────┬───────┘
       │ CrawlResult (URLs + forms + params + headers + cookies)
       ▼
┌─────────────────────────────────────────────────┐
│            Scanner Plugin Registry               │
│                                                 │
│  @register_scanner ← auto-discovers new files   │
│                                                 │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │ XSS  │ │SQLi  │ │CSRF  │ │ Dir  │ │Head  │  │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘  │
│  ┌──────┐ ┌──────┐ ┌──────┐                    │
│  │ SSL  │ │Cook  │ │Redir │  ← all async        │
│  └──────┘ └──────┘ └──────┘                    │
└─────────────────┬───────────────────────────────┘
                  │ list[Vulnerability]
                  ▼
┌──────────────────────────────┐
│       Report Generator       │
│  HTML (dark-themed) + JSON   │
│  + Rich CLI table output     │
└──────────────────────────────┘
```

### Adding a New Scanner

Just drop a file in `vulnhawk/scanners/` — it's **auto-discovered**:

```python
# vulnhawk/scanners/my_scanner.py
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

@register_scanner
class MyScanner(BaseScanner):
    name = "My Scanner"
    description = "Detects something cool"

    async def scan(self, target) -> list[Vulnerability]:
        vulns = []
        # your async scanning logic
        return vulns
```

---

## 🧪 Safe Testing Targets

| Target | Command |
|--------|---------|
| **OWASP Juice Shop** (recommended) | `docker run -p 3000:3000 bkimminich/juice-shop` |
| **DVWA** | `docker run -p 80:80 vulnerables/web-dvwa` |
| **WebGoat** | `docker run -p 8080:8080 webgoat/webgoat` |

---

## 📂 Project Structure

```
vulnhawk/
├── vulnhawk/
│   ├── cli.py                # Typer CLI with Rich terminal output
│   ├── core/
│   │   ├── crawler.py        # Async web crawler (httpx + BeautifulSoup)
│   │   ├── scanner.py        # BaseScanner + @register_scanner plugin system
│   │   └── reporter.py       # HTML + JSON report generator
│   ├── scanners/
│   │   ├── xss.py            # Reflected XSS (params + forms)
│   │   ├── sqli.py           # SQL Injection (error/boolean/time)
│   │   ├── csrf.py           # CSRF token checker
│   │   ├── headers.py        # Security headers analyzer
│   │   ├── directories.py    # Sensitive path enumeration (40+ paths)
│   │   ├── cookies.py        # Cookie flag checker
│   │   ├── open_redirect.py  # URL redirect validator
│   │   └── ssl_tls.py        # SSL/TLS cert + protocol checker
│   └── utils/
│       ├── http_client.py    # Shared async httpx client factory
│       ├── helpers.py        # URL utilities (inject_param, etc.)
│       └── rate_limiter.py   # Token-bucket rate limiter (10 req/s)
├── web/
│   ├── app.py                # FastAPI web dashboard
│   └── templates/
│       └── dashboard.html    # Dark-themed browser UI
├── tests/
│   ├── conftest.py           # Pytest fixtures (mock crawl results)
│   └── test_scanners.py      # Scanner unit tests
├── .github/workflows/ci.yml  # GitHub Actions (matrix: 3.11+3.12)
├── pyproject.toml
└── Dockerfile
```

---

## 🛠️ Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **HTTP** | `httpx` (async) | Non-blocking, connection pooling |
| **HTML parsing** | BeautifulSoup4 | Robust form/link extraction |
| **CLI** | Typer + Rich | Beautiful terminal output |
| **Dashboard** | FastAPI + Jinja2 | Lightweight, async |
| **Rate limiting** | Custom token-bucket | Respectful to target servers |

---

## 🗺️ Roadmap

- [x] 8 scanner modules (XSS, SQLi, CSRF, Headers, Dir, Cookies, Redirect, SSL)
- [x] Plugin-based architecture (drop a file → auto-registered)
- [x] Beautiful HTML + JSON reports
- [x] Rich CLI with progress bars
- [x] Web dashboard
- [x] Rate limiting
- [x] CI/CD (GitHub Actions, matrix testing)
- [x] CVSS 3.1 scoring on all findings
- [x] PDF export (`pip install vulnhawk[pdf]`)
- [x] Authenticated scanning (login flows)
- [x] Subdomain enumeration (9th scanner module)
- [ ] CVSS vector string display

---

*Built as a portfolio project demonstrating async Python, cybersecurity concepts, and plugin-based software architecture.*
