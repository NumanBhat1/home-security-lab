# Brute Force / Weak Authentication

**Severity:** High
**CVSS v3.1:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
**OWASP Top 10:** A07:2021 Identification and Authentication Failures

---

## Description
The login function has no protection against automated password guessing: no rate limiting, no account lockout, and weak password storage. This makes credential brute-forcing viable.

## Environment
- **Target:** Metasploitable 2 / DVWA (Security: Low)
- **Module:** DVWA > Brute Force
- **Tool:** Browser (manual), Hydra (automated, optional)

## Source Code Observation
```php
$password = md5($pass);
```
```sql
SELECT * FROM users WHERE user = '$user' AND password = '$pass';
```
Two problems are visible: passwords are hashed with **MD5** (fast, unsalted, trivially cracked), and there is nothing to limit repeated attempts.

## Proof of Concept
The login form accepts unlimited attempts with no delay, no CAPTCHA, and no lockout. An automated tool can iterate a wordlist against it:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.128.2 http-get-form \
  "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Login failed"
```
The weak default credentials (`admin` / `password`) are recovered quickly.

![Screenshot](./screenshots/09-brute-force.png)

## Business Impact
- Account takeover through credential guessing
- MD5 hashes, if dumped via SQLi, are cracked almost instantly offline
- No lockout means attacks can run indefinitely without detection

## Root Cause
Weak authentication design: fast unsalted hashing (MD5), no rate limiting, no account lockout, no MFA.

## Remediation
- Store passwords with a slow, salted algorithm such as **bcrypt, scrypt, or Argon2**.
- Implement **rate limiting** and **account lockout / progressive delays** after failed attempts.
- Add **multi-factor authentication (MFA)**.
- Add CAPTCHA after repeated failures and monitor/alert on brute-force patterns.
- Enforce a strong password policy.

**References:**
- OWASP: https://owasp.org/www-community/attacks/Brute_force_attack
- CWE-307: https://cwe.mitre.org/data/definitions/307.html
