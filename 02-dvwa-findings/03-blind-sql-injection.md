# Blind SQL Injection

**Severity:** High
**CVSS v3.1:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command
**OWASP Top 10:** A03:2021 Injection

---

## Description
The application is vulnerable to SQL injection, but does not display query results or database errors directly. Instead, the data is inferred from how the application behaves, based on differences in the response (true or false) or in how long the response takes.

## Environment
- **Target:** Metasploitable 2 / DVWA (Security: Low)
- **Module:** DVWA > SQL Injection (Blind)
- **Tool:** Browser

## Proof of Concept

**Boolean-based test:** comparing a condition that is always true against one that is always false:

**Payload (true condition):**
```
1' AND '1'='1
```
Returns the "User ID exists in the database" message.

**Payload (false condition):**
```
1' AND '1'='2
```
Returns "User ID is MISSING from the database."

The difference in responses to logically equivalent inputs confirms the query is being manipulated, even though no data is printed.

![Screenshot](./screenshots/03-blind-sql-injection.png)

## Business Impact
Despite the limited output, an attacker can extract the entire database one bit at a time by asking a series of true/false questions (e.g. "is the first character of the admin password hash 'a'?"). Time-based variants (`SLEEP()`) work even when there is no visible true/false difference. The end result is the same as classic SQLi, full data disclosure. It just takes longer and is normally automated with a tool.

## Root Cause
Same as classic SQL injection: user input concatenated into the query. The only difference is that the application does not echo results, which provides no real protection.

## Remediation
- Use parameterized queries. The fix is identical to classic SQLi.
- Return generic responses that do not leak query state.
- Deploy a WAF to detect automated blind-injection tooling as defense in depth.
- Enforce least-privilege database accounts.

**References:**
- OWASP: https://owasp.org/www-community/attacks/Blind_SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
