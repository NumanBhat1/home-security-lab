# Screenshots

Drop your screenshots here, named to match each finding:

- `01-command-injection.png`  — the `whoami` output showing `www-data`
- `02-sql-injection.png`      — the full list of users returned by `' OR '1'='1`
- `03-blind-sql-injection.png`— the true vs false response difference
- `04-local-file-inclusion.png` — the `/etc/passwd` contents in the browser
- `05-file-upload.png`        — the uploaded shell.php returning "Upload test"
- `06-xss-reflected.png`      — the alert('XSS') popup
- `07-xss-stored.png`         — the stored payload firing on page load
- `08-csrf.png`               — the password-changed confirmation
- `09-brute-force.png`        — recovered credentials / Hydra output

A finding without a screenshot looks unproven. These matter.
