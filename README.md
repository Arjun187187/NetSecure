# NetSecure

### Network Vulnerability Assessment & Security Reporting Platform

NetSecure is a defensive, authorized network security assessment and reporting platform built with **Python**, **Flask**, **Nmap**, and **ReportLab**. Designed for security operations, internal lab assessments, and defensive vulnerability evaluation, NetSecure enables authorized administrators to discover active network assets, enumerate exposed TCP services, perform evidence-based security risk analysis, calculate security posture scores, and generate machine-readable **JSON** reports alongside audit-ready **PDF** assessment reports.

> [!IMPORTANT]
> **AUTHORIZED SECURITY ASSESSMENT NOTICE**  
> NetSecure is strictly intended for defensive evaluation of systems you own or have explicit authorization to assess. Unethical scanning or unauthorized testing against third-party infrastructure is strictly prohibited. Built-in authorization controls enforce explicit confirmation for public targets.

---

## Table of Contents

- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation & Prerequisites](#installation--prerequisites)
- [Running NetSecure](#running-netsecure)
- [User Guide & Platform Workflows](#user-guide--platform-workflows)
- [Authorized Use & Security Controls](#authorized-use--security-controls)
- [Security Boundaries](#security-boundaries)
- [Target Classification Matrix](#target-classification-matrix)
- [Security Posture Scoring Model](#security-posture-scoring-model)
- [Finding Model & Evidence Evaluation](#finding-model--evidence-evaluation)
- [Reporting Engine (JSON & PDF)](#reporting-engine-json--pdf)
- [REST API Reference](#rest-api-reference)
- [Quality Assurance & Security Audit Summary](#quality-assurance--security-audit-summary)
- [Portfolio Value & Demonstrated Skills](#portfolio-value--demonstrated-skills)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Limitations & Future Improvements](#limitations--future-improvements)
- [Contributing & Responsible Disclosure](#contributing--responsible-disclosure)
- [License & Screenshots](#license--screenshots)
- [Project Status](#project-status)

---

## Key Features

- **Target Validation & Classification**: Automated IPv4, loopback, private CIDR, and hostname validation. Prevents command injection and flag manipulation.
- **Controlled Network Discovery**: Multithreaded host reachability probes for authorized private subnets (e.g. `192.168.1.0/24` or `127.0.0.0/29`) with host size safety controls (max 256 addresses per discovery).
- **Service & Version Detection**: TCP socket connectivity checks coupled with Nmap service banner enumeration and version detection.
- **Evidence-Based Security Assessment**: Catalog-based finding evaluation generating observed technical evidence, confidence ratings, security impacts, recommendations, and remediation guidance.
- **NetSecure Security Posture Score**: Transparent, deterministic 0–100 posture score weighted by finding severity and confidence.
- **Security Operations Dashboard**: Responsive single-page dashboard featuring real-time metric counters, posture widgets, severity distribution progress bars, scan history, assets inventory, and slide-over detail modals.
- **Machine-Readable JSON Reporting**: Automatic generation of structured JSON assessment files conforming to a standard schema (`reports/json/`).
- **Audit-Ready PDF Reporting**: Printable A4 PDF security reports generated via **ReportLab**, featuring a cover page, executive summary, technical exposure tables, detailed findings, remediation steps, and two-pass page numbering (`Page X of Y`).
- **Strict Security Boundaries**: Path traversal defenses (`Path.resolve()` checks), non-shell subprocess execution (`shell=False`), public-target authorization gates (HTTP 403 enforcement), and zero automated exploitation tools.

---

## Technology Stack

- **Backend Framework**: Python 3.14.6, Flask 3.1+
- **Scanner Engine**: Python `socket`, `ThreadPoolExecutor`, Nmap 7.99.1 CLI integration
- **PDF & Reporting**: ReportLab 5.0 (PDF generation), JSON schema serializer
- **Frontend Architecture**: Vanilla HTML5, Modern CSS3 (CSS tokens, dark mode theme), JavaScript (ES6+, Fetch API)
- **Environment & Build Tools**: Windows PowerShell, Python `.venv`, Git

---

## System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                 NetSecure Dashboard UI                      │
│            HTML5 / Vanilla CSS3 / JavaScript                │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP REST Requests
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       Flask Web API                         │
│                          (app.py)                           │
└──────┬───────────────────────┬───────────────────────┬──────┘
       │                       │                       │
       ▼                       ▼                       ▼
┌──────────────┐       ┌──────────────┐        ┌──────────────┐
│  Target      │       │ Network      │        │ Host Scanner │
│  Validator   │       │ Discovery    │        │ TCP + Nmap   │
└──────────────┘       └───────┬──────┘        └───────┬──────┘
                               │                       │
                               └───────────┬───────────┘
                                           ▼
                               ┌───────────────────────┐
                               │  Security Assessment  │
                               │  & Posture Risk Engine│
                               │     (scanner.py)      │
                               └───────────┬───────────┘
                                           ▼
                               ┌───────────────────────┐
                               │    Reporting Layer    │
                               │      (reporting/)     │
                               └───────┬───────┬───────┘
                                       │       │
                     ┌─────────────────┘       └─────────────────┐
                     ▼                                           ▼
       ┌───────────────────────────┐               ┌───────────────────────────┐
       │   JSON Report Generator   │               │    PDF Report Generator   │
       │     (json_report.py)      │               │     (pdf_report.py)       │
       └─────────────┬─────────────┘               └─────────────┬─────────────┘
                     │                                           │
                     ▼                                           ▼
       ┌───────────────────────────┐               ┌───────────────────────────┐
       │   reports/json/*.json     │               │    reports/pdf/*.pdf      │
       └───────────────────────────┘               └───────────────────────────┘
```

---

## Project Structure

```text
NetSecure/
│
├── app.py                  # Flask Web API routes & report file endpoints
├── scanner.py              # Core scanning, Nmap runner, risk rules, & posture engine
│
├── reporting/              # Decoupled Reporting Package
│   ├── __init__.py         # Package initialization
│   ├── json_report.py      # Machine-readable JSON report builder
│   └── pdf_report.py       # ReportLab A4 PDF report generator & NumberedCanvas
│
├── templates/
│   └── index.html          # Security Operations Dashboard (Single Page Interface)
│
├── static/
│   └── style.css           # Dark theme stylesheet & UI component styles
│
├── reports/                # Report Artifact Storage Directory
│   ├── json/               # Output directory for JSON reports
│   └── pdf/                # Output directory for PDF reports
│
├── requirements.txt        # Python dependency manifest (Flask, ReportLab)
├── .gitignore              # Git ignore rules for virtualenvs, caches, & reports
└── README.md               # Platform documentation & portfolio reference
```

---

## Installation & Prerequisites

### Prerequisites

1. **Python 3.10+** (Tested on Python 3.14.6)
2. **Nmap 7.9+** installed on system PATH (Tested on Nmap 7.99.1)

#### Verify Installation Commands:

```powershell
python --version
nmap --version
```

### Installation Steps (Windows PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/Arjun187187/NetSecure.git

# 2. Enter project directory
cd NetSecure

# 3. Create virtual environment
python -m venv .venv

# 4. Activate virtual environment
.venv\Scripts\activate

# 5. Install dependencies
pip install -r requirements.txt
```

---

## Running NetSecure

Start the local Flask development server:

```powershell
python app.py
```

Once started, navigate your browser to:

```text
http://127.0.0.1:5000
```

---

## User Guide & Platform Workflows

### 1. Host Security Assessment Workflow
1. Navigate to the **Host Assessment** tab.
2. Input an authorized IP address (e.g. `127.0.0.1`) or target hostname.
3. If the target is classified as `PUBLIC`, check the explicit authorization confirmation box.
4. Click **START ASSESSMENT**.
5. Observe real-time progress indicators while TCP socket checks and Nmap service detection execute.
6. Review the assessment summary, NetSecure Security Posture Score, severity breakdown, technical evidence boxes, and remediation guidance.
7. Click **Download JSON Report** or **Download Professional PDF Report**.

### 2. Network Discovery Workflow
1. Navigate to the **Network Discovery** tab.
2. Enter an authorized private subnet in CIDR notation (e.g. `127.0.0.0/29` or `192.168.1.0/24`).
3. Click **DISCOVER HOSTS**.
4. View the active host table displaying discovered `Asset IDs`, `IP Addresses`, `Hostnames`, `Status`, and `Scope Classification`.
5. Click **Assess Host** on any discovered asset to initiate a host assessment.

### 3. Security Operations Dashboard
- Click **Dashboard** to view aggregate system metrics, active assets, completed assessments, total open findings, overall security posture score, risk distribution bars, top priority findings, and recent scan history.

### 4. Scan History, Assets & Findings Management
- Use the **Assets**, **Scan History**, **Findings**, and **Reports** tabs to filter, search, inspect, and download past assessment results via slide-over modal dialogs.

---

## Authorized Use & Security Controls

NetSecure includes defensive controls to enforce authorized ethical assessment:

- **Public Target Authorization Control**: Public global IP addresses are flagged as `PUBLIC`. Scans cannot be executed without checking an explicit authorization confirmation box, returning an HTTP 403 Forbidden error if unconfirmed.
- **CIDR Safety Limits**: Network discovery is restricted to private subnets with a maximum limit of 256 addresses per request (`MAX_DISCOVERY_HOSTS = 256`). Large ranges like `0.0.0.0/0` are rejected.
- **Subprocess Security**: Nmap subprocesses use explicit list vectors `["nmap", "-sV", ...]` with `shell=False` and a strict 60-second timeout, eliminating command injection risks.
- **Path Traversal Protection**: Report download routes enforce strict filename regex matching (`^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.(json|pdf)$`) and check path resolution boundaries against `REPORT_DIR.resolve()`.

---

## Security Boundaries

NetSecure is strictly a defensive vulnerability assessment and exposure auditing platform. The application intentionally **DOES NOT** provide:

- Exploitation payloads or exploit execution scripts
- Password cracking, credential stuffing, or brute-force engines
- Malware, backdoors, or persistence mechanisms
- Evasion tactics, IDS/IPS bypass techniques, or firewall evasion options
- Destructive network testing, memory corruption, or Denial-of-Service (DoS) tools
- Unrestricted or automated public Internet subnet scanning

The platform focuses solely on host reachability discovery, service banner enumeration, evidence-based security exposure scoring, and audit-ready report generation.

---

## Target Classification Matrix

| Classification | Description | Assessment & Scope Rules |
| :--- | :--- | :--- |
| **`LOOPBACK`** | `127.0.0.1`, `::1`, `localhost` | Allowed for local developer lab assessment. |
| **`PRIVATE`** | RFC 1918 addresses (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`) | Allowed for internal lab & authorized network assessment. |
| **`PUBLIC`** | Global routable IP addresses | Requires explicit user authorization confirmation (HTTP 403 gate). |
| **`HOSTNAME`** | Valid domain names | Resolved to IP address prior to classification and scope checking. |
| **`INVALID`** | Malformed IPs, out-of-range octets, flags, or special chars | Rejected immediately with HTTP 400 validation error. |

---

## Security Posture Scoring Model

The **NetSecure Security Posture Score** evaluates target exposure on a deterministic scale from **0 to 100**:

$$\text{Penalty} = (25 \times N_{\text{CRITICAL}}) + (15 \times N_{\text{HIGH}}) + (8 \times N_{\text{MEDIUM}}) + (3 \times N_{\text{LOW}}) + (0 \times N_{\text{INFO}})$$

$$\text{Posture Score} = \max(0, 100 - \text{Penalty})$$

### Posture Rating Scale:

- **`81 – 100`**: **`STRONG`** — Minimal exposed attack surface.
- **`61 – 80`**: **`GOOD`** — Minor exposure; standard management services exposed.
- **`41 – 60`**: **`MODERATE`** — Meaningful service exposure requiring attention.
- **`21 – 40`**: **`HIGH RISK`** — Significant unencrypted or sensitive database/administrative service exposure.
- **`0 – 20`**: **`CRITICAL RISK`** — Severe multiple unencrypted or management exposures.

*Note: The NetSecure Posture Score is an evidence-weighted assessment metric designed for prioritization within the tested scope. It is not CVSS and does not guarantee complete security.*

---

## Finding Model & Evidence Evaluation

Each finding contains structured attributes based on empirical scan observation:

- `finding_id`: Stable identifier (e.g. `NS-F-001`)
- `asset_id`: Associated asset inventory ID (e.g. `ASSET-001`)
- `assessment_id`: Unique assessment scan ID (e.g. `NS-20261005-171934-C903`)
- `port` / `protocol` / `service` / `version`: Enumerated service banner metadata
- `risk`: Severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- `confidence`: Evidence confidence rating (`HIGH`, `MEDIUM`, `LOW`)
- `title` / `description`: High-level security description
- `evidence`: Observed technical evidence string (e.g. `"TCP port 445 is OPEN via direct socket connection check."`)
- `impact`: Security impact analysis
- `recommendation` / `remediation`: Actionable administrator guidance
- `references`: Reference links (maintained as `[]` to prevent fake CVE creation)

---

## Reporting Engine (JSON & PDF)

### 1. Machine-Readable JSON Reports
JSON reports are saved under `reports/json/NetSecure_NS-<id>.json` containing complete assessment metadata, timing, scanner configuration, posture scores, severity counts, and detailed findings.

### 2. Audit-Ready PDF Reports
PDF reports are generated under `reports/pdf/NetSecure_NS-<id>.pdf` using ReportLab. Visual features include:
- **Cover Page**: Title banner, metadata block, executive summary, and confidentiality notice.
- **Executive Summary & Posture Widget**: Posture score box, rating badge, and severity matrix.
- **Scope & Technical Exposure Table**: Open ports, protocols, service banners, versions, and risk levels.
- **Detailed Security Findings**: Individual finding blocks with monospace evidence boxes, impact analysis, and remediation steps.
- **Prioritized Action Plan & Disclaimer**: Step-by-step remediation guide and defensive legal disclaimer.
- **Two-Pass `NumberedCanvas`**: Computes `Page X of Y` footers and running headers across content pages.

---

## REST API Reference

| Method | Endpoint | Description | Input / Parameters | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/validate-target` | Validates & classifies target input | `{"target": "127.0.0.1"}` | Target classification object |
| `POST` | `/api/scan` | Runs host security assessment | `{"target": "...", "confirmed_authorized": true}` | Scan assessment object + report paths |
| `POST` | `/api/discover` | Runs private CIDR discovery | `{"network": "127.0.0.0/29"}` | Discovery result object + asset list |
| `GET` | `/api/dashboard` | Returns aggregate dashboard metrics | None | Metric counts, posture score, top findings |
| `GET` | `/api/assets` | Returns asset inventory list | None | Array of discovered & assessed assets |
| `GET` | `/api/assets/<id>` | Returns single asset detail + scan history | `<asset_id>` or IP | Asset detail object + assessment history |
| `GET` | `/api/scans` | Returns scan assessment history | None | Array of all completed scans |
| `GET` | `/api/scans/<id>` | Returns single scan assessment record | `<assessment_id>` | Complete scan assessment object |
| `GET` | `/api/findings` | Returns aggregated findings catalog | `?risk=HIGH&confidence=HIGH&search=...` | Filtered findings array |
| `GET` | `/api/findings/<id>` | Returns single finding detail | `<finding_id>` | Finding detail object + scan context |
| `GET` | `/api/reports` | Returns generated report file index | None | Array of JSON and PDF report objects |
| `GET` | `/api/reports/<id>/json` | Downloads JSON report for assessment | `<assessment_id>` | JSON file attachment |
| `GET` | `/api/reports/<id>/pdf` | Downloads PDF report for assessment | `<assessment_id>` | PDF file attachment |
| `GET` | `/reports/json/<filename>` | Direct safe JSON report download | `<filename>.json` | File download |
| `GET` | `/reports/pdf/<filename>` | Direct safe PDF report download | `<filename>.pdf` | File download |

---

## Quality Assurance & Security Audit Summary

Phase 7 testing verified system stability and security hardening:

- **Python Compilation**: Passed clean compilation across all modules (`compileall`).
- **Input Validation**: Verified rejection of malformed IPs, flag injection attempts (`-sV`), long strings, and invalid octets (`192.168.1.999`).
- **Public Target Authorization Gate**: Unconfirmed public target scans correctly return HTTP 403.
- **CIDR Scope Limit**: Subnet size limits (max 256 hosts) and public range blocks verified.
- **Path Traversal Defenses**: Tested illegal traversal URLs (`/reports/json/../app.py`). Access safely blocked.
- **Secret & Credential Audit**: Verified 0 hardcoded passwords, tokens, or private credentials.
- **PDF Report Verification**: Visually inspected generated ReportLab PDF documents for printable layout, header/footer page numbering, table formatting, and flow control.

---

## Portfolio Value & Demonstrated Skills

NetSecure demonstrates practical cybersecurity engineering and software architecture capabilities:

- **Defensive Cybersecurity Engineering**: Authorized vulnerability assessment, service enumeration, and evidence-based risk prioritization.
- **Backend Architecture**: Modular Python/Flask API development, concurrency management (`ThreadPoolExecutor`), and subprocess security.
- **Automated Security Reporting**: ReportLab PDF document engineering, dynamic two-pass canvas layout, and JSON schema design.
- **Security Operations UI/UX**: Professional dark theme dashboard, real-time status feedback, and responsive data visualizers.
- **Secure Coding Practices**: Input sanitization, path traversal defenses, non-shell command execution, and clean error handling.

---

## Troubleshooting & FAQ

### 1. Nmap is reported as unavailable
- **Cause**: Nmap is not installed or not added to system PATH.
- **Solution**: Install Nmap from [nmap.org](https://nmap.org/download.html) and add `nmap` to your system environment variables. NetSecure will gracefully fallback to standard socket probes if Nmap is unavailable.

### 2. Port 5000 is already in use
- **Cause**: Another service or Flask instance is bound to port 5000.
- **Solution**: Edit line 461 in `app.py` to change `port=5000` to `port=5001` or another open port.

### 3. PDF report download fails
- **Cause**: Missing `reportlab` dependency.
- **Solution**: Run `pip install -r requirements.txt` within your activated virtual environment.

---

## Limitations & Future Improvements

### Current Limitations
- **Defensive Non-Exploitative Scope**: Assesses service exposure and banner information without executing exploitation.
- **Common Port Scope**: Evaluates standard common TCP management ports.
- **Non-Authenticated Assessment**: Performs network-level service discovery without local agent credentials.

### Future Enhancements Roadmap
- Verified vulnerability intelligence database (NVD/CVE API) integration.
- Authenticated local host compliance checks.
- Scheduled recurring network assessment timers.
- Multi-user Role-Based Access Control (RBAC).

---

## Contributing & Responsible Disclosure

### Contributing
Contributions to enhance defensive scanner capabilities, report templates, or UI visualizers are welcome:
1. Fork the repository and create a feature branch (`git checkout -b feature/improvement`).
2. Implement your changes following established security boundaries and code formatting.
3. Run syntax compilation (`python -m compileall .`) and local testing.
4. Submit a detailed Pull Request.

### Responsible Security Disclosure
If you discover a security vulnerability within NetSecure itself, please report it responsibly by contacting the project maintainer via GitHub issues or email before public disclosure.

---

## License & Screenshots

### License
This project is currently maintained as a personal cybersecurity portfolio project. License terms may be designated prior to general public open-source distribution.

### Screenshots & Demos
High-resolution interface screenshots and walk-through demonstrations will be added to the repository assets upon final tagged release.

---

## Project Status

- **Current Version**: `1.0.0-rc`
- **Development Status**: Active / Security Portfolio Project
- **Maintainer**: Arjun C S ([GitHub Repository](https://github.com/Arjun187187/NetSecure))

