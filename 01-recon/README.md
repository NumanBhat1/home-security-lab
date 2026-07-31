# Reconnaissance

Host discovery, port scanning, and service enumeration against the Metasploitable 2 target (`192.168.128.2`) from the Kali attacker VM.

## Tools & artifacts

| File | Tool | What it captured |
|---|---|---|
| [`nmap-full-scan.txt`](./nmap-full-scan.txt) | Nmap `-sV -sC` | Open ports, service versions, default-script output |
| [`whatweb-scan.txt`](./whatweb-scan.txt) | WhatWeb | Web technology fingerprint (Apache, PHP, WebDAV) |
| [`nikto-scan.txt`](./nikto-scan.txt) | Nikto | Web server misconfigurations and exposed files |
| [`smb-enumeration.txt`](./smb-enumeration.txt) | enum4linux | SMB users, shares, and password policy |

## Exposed services (from the Nmap scan)

| Port | Service | Version | Notable |
|---|---|---|---|
| 21 | FTP | vsftpd 2.3.4 | Anonymous login allowed; version carries a known backdoor (CVE-2011-2523) |
| 22 | SSH | OpenSSH 4.7p1 | End-of-life |
| 23 | Telnet | Linux telnetd | Cleartext authentication |
| 25 | SMTP | Postfix | SSLv2 supported; expired 2010 certificate |
| 53 | DNS | ISC BIND 9.4.2 | Version disclosed |
| 80 | HTTP | Apache 2.2.8 / PHP 5.2.4 | Hosts DVWA; phpinfo.php and phpMyAdmin exposed; WebDAV enabled |
| 111 | rpcbind | RPC 2 | Exposes NFS/mountd |
| 139/445 | SMB | Samba 3.0.20-Debian | usermap_script RCE (CVE-2007-2447); NULL sessions; signing disabled |
| 512/513/514 | r-services | rexec / rlogin / rsh | Legacy cleartext remote access |
| 1099 | Java RMI | GNU Classpath | Remote class loading risk |
| 1524 | bindshell | Metasploitable root shell | **Direct root shell — instant compromise** |
| 2049 | NFS | RPC 100003 | Potential exported shares |
| 2121 | FTP | ProFTPD 1.3.1 | Secondary FTP daemon |
| 3306 | MySQL | 5.0.51a | Reachable over network |
| 5432 | PostgreSQL | 8.3 | Reachable over network |
| 5900 | VNC | protocol 3.3 | Weak VNC auth |
| 6000 | X11 | — | Access denied but exposed |
| 6667 | IRC | UnrealIRCd | Backdoored build (CVE-2010-2075) |
| 8009 | AJP13 | Apache Jserv | Tomcat connector |
| 8180 | HTTP | Apache Tomcat 5.5 | Default manager credentials common |

## Summary

The target exposes **23 open ports** running services that are, without exception, years past end-of-life. The attack surface includes at least one **immediate root shell** (port 1524), multiple services with **known remote-code-execution CVEs** (vsftpd 2.3.4, Samba usermap_script, UnrealIRCd), **cleartext protocols** (Telnet, r-services), and a web stack (Apache 2.2.8 / PHP 5.2.4) hosting DVWA plus an unprotected phpMyAdmin and a phpinfo() page.

SMB enumeration is especially damaging: **NULL sessions are permitted**, allowing an unauthenticated attacker to retrieve the full list of 35 system accounts (including `root` and `msfadmin`) and read the `tmp` share. Combined with a password policy that has **no complexity, no lockout, and no minimum length**, this hands an attacker a ready-made username list and a target with no brute-force protection.

The web application testing that follows in [`../02-dvwa-findings/`](../02-dvwa-findings/) exploits this surface in detail.
