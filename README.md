# Home Security Lab

A personal cybersecurity lab for hands-on offensive and defensive practice, built across an Apple Silicon Mac (UTM hypervisor) and a Windows desktop. Used for vulnerability assessment, web application penetration testing, and SIEM/detection engineering.

Maintained by **Numan Khalid Bhat**, CompTIA Security+ (SY0-701) certified.
LinkedIn: [linkedin.com/in/numanbhat](https://www.linkedin.com/in/numanbhat) · Credly: [credly.com/users/numanbhat](https://www.credly.com/users/numanbhat)

---

## Lab Architecture

| VM / Host | OS | Role | Network |
|---|---|---|---|
| Kali Linux (ARM64) | Debian-based | Attacker | UTM Shared (NAT), isolated |
| Metasploitable 2 (x86_64) | Ubuntu 8.04 | Vulnerable target | UTM Shared (NAT), isolated |
| Windows Desktop | Windows 10/11 | Endpoint telemetry / Sysmon | Lab network |

**Isolation note:** The Metasploitable 2 target is intentionally vulnerable and is never exposed to the internet. Both lab VMs run on UTM's Shared Network, segregated from production and the wider network.

---

## Contents

### `01-recon/`: Reconnaissance
Network discovery and service enumeration against the Metasploitable 2 target.
- Nmap full port + version scan
- Nikto web server scan
- WhatWeb technology fingerprinting
- SMB enumeration

### `02-dvwa-findings/`: Web Application Testing
Manual exploitation of **9 vulnerability classes** in Damn Vulnerable Web Application (DVWA, security level: Low), mapped to the OWASP Top 10. Each finding documents the payload, proof of concept, business impact, root cause, and remediation.

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

### `03-va-report/`: Vulnerability Assessment Report
Consolidated professional VA report on the Metasploitable 2 target (executive summary, scope, findings, business impact, remediation).

### `04-siem/`: SIEM & Detection Engineering
Splunk SOC portfolio: four detections across the attack kill chain (network recon, web attack, SSH brute force, Linux auth/persistence) mapped to MITRE ATT&CK, with dashboards, scheduled alerts, sample logs, per-project screenshots, and a cross-source kill-chain correlation of a single attacker.

### `05-windows/`: Windows Endpoint & Telemetry *(in progress)*
Sysmon deployment, Windows Event log analysis, and endpoint detection on real Windows hardware.

---

## Tools Used
Nmap · Nikto · WhatWeb · Burp Suite · DVWA · Metasploitable 2 · Splunk · Sysmon · MITRE ATT&CK Navigator · Kali Linux · UTM

## Skills Demonstrated
Network reconnaissance · Vulnerability assessment · Web application penetration testing · OWASP Top 10 exploitation · Manual exploitation · SIEM deployment · Detection engineering · Alert triage · Security reporting · Risk assessment · Remediation guidance

---

## Legal & Ethical Note
All testing was performed against intentionally vulnerable systems (DVWA, Metasploitable 2) that I own and run inside an isolated lab. No systems belonging to any third party were tested.
