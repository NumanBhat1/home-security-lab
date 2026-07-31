# Screenshots

Evidence captured during the DVWA web application testing. Each image is referenced from its matching finding file.

| File | Finding |
|---|---|
| `01-command-injection.png` | `whoami` output showing `www-data` |
| `02-sql-injection.png` | full user list returned by `' OR '1'='1` |
| `04-local-file-inclusion.png` | `/etc/passwd` contents in the browser |
| `05-file-upload.png` | uploaded `shell.php` returning "Upload test" |
| `06-xss-reflected.png` | `alert('XSS')` popup on the reflected page |
| `07-xss-stored.png` | stored payload firing on page load |
| `08-csrf.png` | password-changed confirmation |

Blind SQL Injection (03) and Brute Force (09) are evidenced through application behaviour and source code rather than a single screenshot, as explained in their finding files.
