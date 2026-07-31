# Vulnerability Assessment Report

This folder holds the consolidated report for the assessment of the Metasploitable 2 target.

**[Metasploitable2_VA_Report.pdf](./Metasploitable2_VA_Report.pdf)**

## What it is

A full vulnerability assessment of the host `192.168.128.2`, written the way a real engagement report would be. It pulls together the reconnaissance in [`../01-recon/`](../01-recon/) and the hands-on exploitation in [`../02-dvwa-findings/`](../02-dvwa-findings/) into one document aimed at both a technical reader and a manager.

## What it covers

The host was scanned to map its attack surface, and the important issues were then confirmed by hand to prove what an attacker could actually do. The report documents **19 findings** across two layers:

- **Infrastructure (10 findings):** the exposed network services, including an unauthenticated root shell on port 1524, the vsftpd 2.3.4 / Samba / UnrealIRCd backdoors, anonymous SMB access, and an absent password policy.
- **Web application (9 findings):** manual exploitation of the hosted DVWA app, covering command injection, SQL injection, file upload, local file inclusion, stored and reflected XSS, CSRF, and credential brute force.

By severity: **7 Critical, 8 High, 4 Medium.** Overall rating: Critical.

## How the report is laid out

| Section | Contents |
|---|---|
| Executive Summary | Plain-language overview and the severity breakdown |
| Scope & Objectives | What was tested and the rules of engagement |
| Methodology | The tools and phases used |
| Risk Rating Definitions | How severity maps to CVSS |
| Summary of Findings | All 19 findings in one table |
| Detailed Findings | Each issue with evidence, impact, and remediation |
| Remediation Roadmap | Fixes ordered by priority |
| Conclusion | Overall assessment |
| Appendix | Raw scan output |

Each web finding includes a screenshot captured during testing, so the proof of concept is visible rather than just described.

## Tools used

Nmap, WhatWeb, Nikto, enum4linux, and manual browser-based testing against DVWA.

## Note

All testing was done against a system I own and run inside an isolated lab. Nothing outside that lab was touched. The target is intentionally vulnerable and was never exposed to the internet.
