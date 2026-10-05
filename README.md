# NetSecure — Network Vulnerability Assessment & Reporting Tool

A Python/Flask security assessment project for **authorized lab environments**.

## Features

- TCP port discovery for common ports
- Service identification
- Optional Nmap service/version enumeration
- Heuristic risk classification
- Security recommendations
- Web dashboard
- JSON report generation

## Tech Stack

Python, Flask, Socket Programming, Nmap, HTML, CSS, JavaScript, Linux

## Setup — Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install nmap python3-venv -y

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Windows

Install Python and Nmap, then:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

## Testing

Use `127.0.0.1` or an isolated VirtualBox machine that you own/control.

Example lab workflow:

```text
Kali Linux (scanner)
       |
       | VirtualBox Host-Only Network
       |
Ubuntu/Metasploitable (authorized target)
```

## Important

This project is intended for systems you own or have explicit permission to assess. It is a vulnerability-assessment/reporting tool, not an exploitation framework.
