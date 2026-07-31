# Windows Endpoint & Telemetry

Your Windows desktop closes one of the biggest gaps on the Deloitte IR JD: **"experience with Windows/Linux OS logs"** and **Sysmon / endpoint telemetry**. On real hardware this is far easier than running Windows-on-ARM inside UTM, and it's genuinely representative of what a SOC analyst looks at every day.

> **Important, do this safely.** Do NOT run attacks against your real Windows desktop or install intentionally vulnerable software on it. The Windows box is the **monitored endpoint** (the thing generating logs you analyse), not a target. Keep the vulnerable target (Metasploitable/DVWA) on the isolated Mac VMs. This is exactly how it works in a real SOC: you monitor production endpoints, you don't attack them.

---

## What to build here (in order)

### Step 1: Install Sysmon with a good config
Sysmon (System Monitor) is a free Microsoft Sysinternals tool that logs rich endpoint telemetry: process creation, network connections, file/registry changes, and more. It's the single most valuable free source of endpoint detection data.

1. Download Sysmon from Microsoft Sysinternals: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Download the standard community config (SwiftOnSecurity):
   https://github.com/SwiftOnSecurity/sysmon-config
3. Install (run PowerShell/CMD **as Administrator**):
   ```
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Confirm it's logging: open **Event Viewer** →
   `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`

**Document here:** `sysmon-setup.md`, what you installed, the config you used, and a screenshot of Sysmon events in Event Viewer.

### Step 2: Learn the key Windows Event IDs
These are the ones interviewers actually ask about. Write a cheatsheet file (`windows-event-ids.md`) covering:

| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | **Failed logon** (brute force indicator) |
| 4634 / 4647 | Security | Logoff |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4688 | Security | Process creation |
| 4720 | Security | User account created |
| 4728 / 4732 | Security | User added to privileged group |
| 7045 | System | New service installed (persistence) |
| Sysmon 1 | Sysmon | Process creation (richer than 4688) |
| Sysmon 3 | Sysmon | Network connection |
| Sysmon 11 | Sysmon | File created |

### Step 3: Generate and hunt for benign "suspicious" activity
Safely, on your own box, run normal recon-style commands and then find them in the logs. This is the analyst skill, connecting an action to its log trail:
```
whoami
net user
net localgroup administrators
systeminfo
ipconfig /all
```
Then open Event Viewer / Sysmon Operational and find the **Sysmon Event ID 1** (process creation) entries for `whoami.exe`, `net.exe`, etc.

**Document here:** `04-recon-detection.md`, the command you ran, the matching Sysmon event (screenshot), and the MITRE technique:
- `whoami` → **T1033** System Owner/User Discovery
- `net user` / `net localgroup` → **T1087** Account Discovery
- `systeminfo` → **T1082** System Information Discovery

### Step 4 (later): Ship Windows logs to Splunk
Once Splunk is running on your Kali VM (see `../04-siem/`), install the **Splunk Universal Forwarder** on Windows and forward the Security, System, and `Microsoft-Windows-Sysmon/Operational` logs. Now you have Windows telemetry landing in your SIEM, which is precisely the Deloitte JD requirement.

---

## Why this matters for your applications
The Deloitte IR JD lists "Windows/Linux OS logs" and endpoint telemetry as required. Before your Windows desktop, your lab was Linux-only, a visible hole. Now you can honestly write:

> *Deployed Sysmon on a Windows endpoint, analysed Windows Security and Sysmon event logs, and mapped host activity (process creation, account discovery) to MITRE ATT&CK techniques.*

That's a real, defensible line that most fresher applicants can't write.
