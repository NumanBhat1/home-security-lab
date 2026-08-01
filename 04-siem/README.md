# SOC / Incident Response Portfolio: Splunk Detection Engineering

**Author:** Numan Khalid Bhat · **Target role:** SOC Analyst / Incident Response · CompTIA Security+ (SY0-701)
**Platform:** Splunk Enterprise (home lab) · **Framework:** MITRE ATT&CK

A hands-on SOC detection portfolio built in a self-hosted lab (Kali Linux, Metasploitable 2, Windows, DVWA, Splunk Enterprise). Each project ingests log data, detects attacks with SPL, visualises findings in dashboards, and fires scheduled alerts, with triage-to-containment incident notes and MITRE ATT&CK mapping.

> **Data provenance (read this):** the detections were developed and tested against representative **sample log data** (`auth.log`, `apache_access.log`, `firewall.log`) so the SPL, dashboards, and alerts could be built and proven end to end. The SSH brute force is additionally reproduced **live** with Hydra against Metasploitable (see `02_Hydra_Live_Attack_Reproduction.md`). Sample-data screenshots are labelled as such; the live run is the real-attack validation.

---

## The through-line: one attacker, full kill chain
All four detections track the same attacker IP (`192.168.56.104`) across four data sources, reconstructing a complete intrusion:

| Phase | Detection | Data source | Index | What's detected | MITRE |
|---|---|---|---|---|---|
| 1. Reconnaissance | Network Recon | Firewall (UFW/iptables) | `network` | Port scans, host sweeps, service targeting | T1046, T1018, T1595 |
| 2. Initial Access (web) | Web Attack | Apache `access_combined` | `web` | SQLi, XSS, command injection, LFI, scanners | T1190, T1059 |
| 3. Credential Access | SSH Brute Force | Linux `auth.log` | `linux` | Brute force + successful compromise | T1110, T1078 |
| 4. Priv-Esc / Persistence | Linux Auth Monitoring | Linux `auth.log` | `linux` | Sudo abuse, unauthorised sudo, new root accounts | T1548.003, T1136.001 |

**Capstone correlation**, one search reconstructs the whole chain (screenshot in `screenshots/killchain-correlation.jpeg`):
```spl
(index=network OR index=linux OR index=web) "192.168.56.104"
| sort _time
```

---

## Contents

| File | What it is |
|---|---|
| `00_Splunk_Beginner_Complete_Walkthrough.md` | Zero-to-running Splunk: index creation, data ingestion, first search |
| `01_SSH_Brute_Force_Detection.md` | Brute force detection + success-after-failure compromise correlation |
| `02_Hydra_Live_Attack_Reproduction.md` | Reproduce the SSH attack live with Hydra against Metasploitable |
| `03_Splunk_Dashboard_and_Alert.md` | Dashboard + alert reference (incl. Simple XML) |
| `04_Linux_Authentication_Monitoring.md` | Logins, sudo abuse, unauthorised account creation (caught a UID=0 persistence account) |
| `05_Web_Attack_Detection.md` | SQLi / XSS / command injection / path traversal / scanner detection over Apache logs |
| `06_Network_Recon_Detection.md` | Port scans, ping sweeps, service targeting from firewall logs |
| `detections/` | Standalone SPL files per rule |
| `screenshots/` | Splunk evidence (dashboards, alerts, search results) |

---

## Skills demonstrated (maps to the Deloitte IR Consultant JD)
- **SIEM monitoring & detection engineering**: SPL: `rex`, `stats`, `dc`, `eval/case`, `timechart`, `where`, `regex`, `urldecode`
- **Alert triage & investigation**: severity models, success-vs-attempt analysis, source pivoting
- **Incident response**: triage → investigation → containment → recommendations, per detection
- **MITRE ATT&CK**: every detection mapped to tactics and techniques
- **Cross-source correlation**: reconstructing a kill chain across firewall, host, and web logs
- **Data onboarding**: index creation, sourcetype selection (`linux_secure`, `access_combined`, `syslog`), field extraction

---

## Interview one-liner
> "I built a Splunk detection portfolio that follows a single attacker across four data sources, firewall, web, and Linux auth logs, detecting each phase of the kill chain from port scan to brute force to web exploitation to a root-level persistence account, and I can correlate all of it in one search to reconstruct the full incident."
