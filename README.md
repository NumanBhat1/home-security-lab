# Home Security Lab

A self-hosted lab for hands-on offensive and defensive security work: vulnerability assessment, web application testing, and SIEM detection engineering, built on UTM virtualization with Splunk Enterprise for analysis.

Maintained by **Numan Khalid Bhat**, CompTIA Security+ (SY0-701).
[linkedin.com/in/numanbhat](https://www.linkedin.com/in/numanbhat) · [credly.com/users/numanbhat](https://www.credly.com/users/numanbhat)

---

## Lab architecture

| Host | OS | Role | Network |
|---|---|---|---|
| Kali Linux | Debian-based | Attacker | Isolated (NAT) |
| Metasploitable 2 | Ubuntu 8.04 | Vulnerable target | Isolated (NAT) |
| Splunk Enterprise | — | SIEM / log analysis | Lab |

The Metasploitable 2 target is intentionally vulnerable and is never exposed to the internet; the lab is segregated from any production or wider network.

---

## Contents

### `01-recon/` — Reconnaissance
Host discovery and service enumeration against the Metasploitable 2 target with Nmap, Nikto, WhatWeb, and SMB enumeration.

### `02-dvwa-findings/` — Web application testing
Manual exploitation of nine vulnerability classes in DVWA (security level: Low), mapped to the OWASP Top 10. Each finding documents the payload, proof of concept, impact, root cause, and remediation.

| # | Finding | OWASP 2021 | Severity |
|---|---|---|---|
| 01 | Command Injection | A03 Injection | Critical |
| 02 | SQL Injection | A03 Injection | Critical |
| 03 | Blind SQL Injection | A03 Injection | High |
| 04 | Local File Inclusion | A01 Broken Access Control | High |
| 05 | Unrestricted File Upload | A04 Insecure Design | Critical |
| 06 | Reflected XSS | A03 Injection | Medium |
| 07 | Stored XSS | A03 Injection | High |
| 08 | CSRF | A01 Broken Access Control | Medium |
| 09 | Brute Force / Weak Auth | A07 Identification & Auth Failures | High |

### `03-va-report/` — Vulnerability assessment report
Consolidated report on the Metasploitable 2 target: executive summary, scope, findings, impact, and remediation.

### `04-siem/` — Splunk detection lab
Four Splunk detections across the attack kill chain (network recon, web attack, SSH brute force, Linux auth/persistence), each with SPL, dashboards, scheduled alerts, sample logs, screenshots, and a MITRE ATT&CK mapping, tied together by a single attacker correlated across all data sources.

---

## Tools
Nmap · Nikto · WhatWeb · enum4linux · Burp Suite · DVWA · Metasploitable 2 · Hydra · Splunk Enterprise · SPL · MITRE ATT&CK

## Note
All testing was performed against intentionally vulnerable systems (DVWA, Metasploitable 2) that I own and run inside an isolated lab. No third-party systems were tested.
