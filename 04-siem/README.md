# SIEM & Detection Engineering

Splunk-based detection lab. Attacks are run from Kali against Metasploitable; the goal is to **catch** them in Splunk, write a detection rule, and document the investigation.

## Build order
1. Install **Splunk Enterprise Free** inside the Kali VM (native ARM64 `.tgz` from splunk.com; free licence = 500 MB/day).
2. Onboard Linux logs from Metasploitable (`/var/log/auth.log`, `syslog`, Apache logs), or a universal forwarder.
3. Onboard Windows + Sysmon logs from the Windows desktop (see `../05-windows/`).
4. For each attack, write the detection search, save it as an alert, and write an investigation.

## Structure
```
04-siem/
├── splunk-setup.md          ← install notes, data onboarding, forwarder config
├── detections/              ← one .spl file per rule (SPL + ATT&CK ID + logic)
└── investigations/          ← alert → triage → verdict → recommendation writeups
```

## Detection backlog (attack → detect)

| Attack (from Kali) | MITRE ATT&CK | Detect in Splunk by |
|---|---|---|
| `nmap -sV -p-` | T1046 Network Service Discovery | burst of connections across many ports from one source IP |
| Hydra SSH brute force | T1110 Brute Force | many `Failed password` in auth.log, then a success |
| vsftpd 2.3.4 backdoor | T1190 Exploit Public-Facing App | unexpected shell / traffic on port 6200 |
| Samba usermap_script (CVE-2007-2447) | T1190 | anomalous smbd child process |
| Windows recon (whoami/net user) | T1033 / T1087 | Sysmon Event ID 1 process creation |

See `detections/T1110-ssh-brute-force.spl` for a worked example of the format to follow.
