# SOC / Incident Response Portfolio: Splunk Detection Engineering

**Author:** Numan Khalid Bhat · **Target role:** SOC Analyst / Incident Response · CompTIA Security+ (SY0-701)
**Platform:** Splunk Enterprise (home lab) · **Framework:** MITRE ATT&CK

A Splunk detection portfolio built in a self-hosted lab (Kali Linux, Metasploitable 2, DVWA, Splunk Enterprise). Four detections span the attack kill chain, each with SPL, a dashboard, a scheduled alert, and MITRE ATT&CK mapping, tied together by a single attacker IP correlated across all data sources.

> **Data note:** detections were built and proven against sample log data (in `sample-logs/`) so the SPL, dashboards, and alerts could be validated end to end. The SSH brute force was also reproduced live with Hydra against Metasploitable. Screenshots are in `screenshots/`.

---

## One attacker, full kill chain
All four detections track the same attacker IP (`192.168.56.104`) across four data sources:

| Phase | Detection | Data source | Index | SPL | Screenshots |
|---|---|---|---|---|---|
| 1. Reconnaissance | Network recon (port scans, host sweeps, service targeting) | Firewall (UFW) | `network` | `detections/T1595-network-recon.spl` | `screenshots/network-recon/` |
| 2. Initial access (web) | Web attack (SQLi, XSS, cmd injection, LFI, scanners) | Apache `access_combined` | `web` | `detections/T1190-web-attack-detection.spl` | `screenshots/web-attack/` |
| 3. Credential access | SSH brute force + successful compromise | Linux `auth.log` | `linux` | `detections/T1110-ssh-brute-force.spl` | `screenshots/ssh-brute-force/` |
| 4. Priv-esc / persistence | Linux auth: sudo abuse, unauthorised sudo, new root account | Linux `auth.log` | `linux` | `detections/T1548-linux-auth-monitoring.spl` | `screenshots/linux-auth/` |

**Capstone correlation** reconstructs the whole intrusion in one search (`screenshots/killchain-correlation.jpeg`):
```spl
(index=network OR index=linux OR index=web) "192.168.56.104"
| sort _time
```

---

## Headline result
The SSH detection separates a *blocked* brute force from a *real compromise*: correlating failed and successful logins from the same source surfaced **192.168.56.104 with 148 failed attempts and 1 success**, compromising `msfadmin`, followed by sudo escalation to root. That single correlated row is the security incident.

---

## Repository layout
```
04-siem/
├── README.md                 (this file)
├── detections/               one .spl per detection: SPL + MITRE ID + logic
├── sample-logs/              auth.log, auth_extended.log, apache_access.log, firewall.log
└── screenshots/              per-detection Splunk evidence + kill-chain correlation
```

---

## Skills demonstrated (maps to the Deloitte IR Consultant JD)
- **SIEM detection engineering** in SPL: `rex`, `stats`, `dc`, `eval/case`, `bin`, `timechart`, `where`, `regex`
- **Alert triage & investigation**: separating attempts from confirmed compromise, source pivoting, severity
- **Incident response**: triage → investigation → containment recommendations per detection
- **MITRE ATT&CK** mapping on every detection
- **Cross-source correlation**: one attacker reconstructed across firewall, web, and auth logs
- **Data onboarding**: index creation, sourcetype selection (`linux_secure`, `access_combined`, `syslog`), field extraction

---

## Interview one-liner
> "I built a Splunk detection portfolio that follows a single attacker across firewall, web, and Linux auth logs, detecting each phase of the kill chain from port scan to brute force to web exploitation to a root-level persistence account, and I correlate all of it in one search to reconstruct the full incident."
