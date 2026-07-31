# Reconnaissance

Host discovery, port scanning, and service enumeration against the Metasploitable 2 target (`192.168.128.2`).

## Files to add here (paste your real output)

| File | Command to generate it |
|---|---|
| `nmap-full-scan.txt` | `nmap -sV -sC -p- -oN nmap-full-scan.txt 192.168.128.2` |
| `nikto-scan.txt` | `nikto -h http://192.168.128.2 -o nikto-scan.txt` |
| `whatweb-scan.txt` | `whatweb http://192.168.128.2 > whatweb-scan.txt` |
| `smb-enumeration.txt` | `enum4linux -a 192.168.128.2 > smb-enumeration.txt` |

> **TODO (you):** run each command in Kali, then paste the output into the matching file. The Nmap scan is the single most important artifact — it establishes the attack surface everything else builds on.

## Summary of exposed services (fill in from your Nmap output)

| Port | Service | Version | Notable |
|---|---|---|---|
| 21 | FTP | vsftpd 2.3.4 | Backdoor (CVE-2011-2523) |
| 22 | SSH | OpenSSH 4.7p1 | |
| 23 | Telnet | | Cleartext auth |
| 25 | SMTP | Postfix | |
| 80 | HTTP | Apache 2.2.8 | Hosts DVWA |
| 139/445 | SMB | Samba 3.x | usermap_script (CVE-2007-2447) |
| 3306 | MySQL | 5.0.51a | |
| 5432 | PostgreSQL | 8.3 | |
| 8180 | HTTP | Tomcat 5.5 | |

*(Confirm versions against your actual scan — the above is the standard Metasploitable 2 profile.)*
