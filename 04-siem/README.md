# Splunk Detection Lab

A self-hosted Splunk Enterprise lab (Kali Linux, Metasploitable 2, DVWA) with four detections covering an attack from reconnaissance through to persistence. Each detection has its SPL, a dashboard, a scheduled alert, and a MITRE ATT&CK mapping. A single attacker IP is correlated across every data source to reconstruct the intrusion.

Logs here are lab-generated sample data used to develop and validate the searches; the SSH brute force was also reproduced live with Hydra against Metasploitable.

## Detections

| Phase | Detection | Data source | Index | SPL | Evidence |
|---|---|---|---|---|---|
| Reconnaissance | Port scans, host sweeps, service targeting | Firewall (UFW) | `network` | `detections/T1595-network-recon.spl` | `screenshots/network-recon/` |
| Initial access (web) | SQLi, XSS, command injection, LFI, scanners | Apache `access_combined` | `web` | `detections/T1190-web-attack-detection.spl` | `screenshots/web-attack/` |
| Credential access | SSH brute force and successful compromise | Linux `auth.log` | `linux` | `detections/T1110-ssh-brute-force.spl` | `screenshots/ssh-brute-force/` |
| Priv-esc / persistence | Sudo abuse, unauthorised sudo, new root account | Linux `auth.log` | `linux` | `detections/T1548-linux-auth-monitoring.spl` | `screenshots/linux-auth/` |

## Kill-chain correlation

A single search ties the whole intrusion together by the attacker IP (`screenshots/killchain-correlation.jpeg`):

```spl
(index=network OR index=linux OR index=web) "192.168.56.104"
| sort _time
```

## Notable result

The SSH detection distinguishes a blocked brute force from an actual compromise by correlating failed and successful logins from the same source. That surfaced `192.168.56.104` with 148 failed attempts and one success against `msfadmin`, followed by sudo escalation to root — the single row that represents the real incident.

## Layout

```
04-siem/
├── detections/     one .spl per detection (SPL, MITRE ID, logic)
├── sample-logs/    auth.log, auth_extended.log, apache_access.log, firewall.log
└── screenshots/    per-detection Splunk evidence + kill-chain correlation
```

## Tools

Splunk Enterprise · SPL · MITRE ATT&CK · Kali Linux · Metasploitable 2 · DVWA · Hydra
