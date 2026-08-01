# Splunk Dashboard & Alert: SSH Brute Force Detection

Builds the visual layer on top of the detection. Two ways in: click-through (learn the UI) or paste the Simple XML (instant, exact). Do the click-through once so you can explain it; keep the XML as a backup.

> All queries assume `index=main sourcetype=linux_secure`. Change the index if you used `linux`.

---

## Part A: Build Each Panel (click-through)

### Panel 1: Failed Logins Over Time
Shows the burst visually, a flat line that spikes is the attack.
```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1m count AS failed_logins
```
Save As → Dashboard Panel → new dashboard **"SSH Brute Force Detection"** → visualization: **Column / Line chart**.

### Panel 2: Top Source IPs by Failed Attempts
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count AS failed_attempts by src_ip
| sort - failed_attempts
| head 10
```
Visualization: **Bar chart**. The attacker IP towers over everything.

### Panel 3: Usernames Targeted (spray detection)
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count AS attempts, dc(user) AS distinct_users, values(user) AS usernames by src_ip
| sort - attempts
```
Visualization: **Statistics table**.

### Panel 4: Successful Compromise (THE money panel)
```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "Failed password for (?:invalid user )?(?<f_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex "Accepted password for (?<s_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval outcome=if(isnotnull(f_user),"failed","success")
| stats count(eval(outcome="failed")) AS failures,
        count(eval(outcome="success")) AS successes,
        values(s_user) AS compromised_user by src_ip
| where failures >= 20 AND successes >= 1
```
Visualization: **Statistics table**. Colour-flag with a table format rule (red when successes ≥ 1).

### Panel 5: Post-Compromise sudo Activity
```spl
index=main sourcetype=linux_secure "sudo:" "COMMAND="
| rex "sudo:\s+(?<user>\S+)\s+:.*USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.*)"
| table _time, user, target_user, command
| sort _time
```
Visualization: **Statistics table**.

**Layout tip:** row 1 = Panel 1 (full width), row 2 = Panels 2 + 3 side by side, row 3 = Panel 4 (full width, highlighted), row 4 = Panel 5.

---

## Part B: Instant Dashboard via Simple XML
*Dashboards → Create New Dashboard → give it a title → Edit → Source → paste this → Save.* Adjust `index=main` if needed.

```xml
<dashboard version="1.1" theme="dark">
  <label>SSH Brute Force Detection</label>
  <description>Detects SSH password brute force and successful compromise on Linux hosts. MITRE T1110 / T1078 / T1548.</description>
  <row>
    <panel>
      <title>Failed SSH Logins Over Time</title>
      <chart>
        <search>
          <query>index=main sourcetype=linux_secure "Failed password" | timechart span=1m count AS failed_logins</query>
          <earliest>-24h</earliest><latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Failed Logins</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Top Source IPs by Failed Attempts</title>
      <chart>
        <search>
          <query>index=main sourcetype=linux_secure "Failed password" | rex "from (?&lt;src_ip&gt;\d{1,3}(?:\.\d{1,3}){3})" | stats count AS failed_attempts by src_ip | sort - failed_attempts | head 10</query>
          <earliest>-24h</earliest><latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Usernames Targeted per Source IP</title>
      <table>
        <search>
          <query>index=main sourcetype=linux_secure "Failed password" | rex "Failed password for (?:invalid user )?(?&lt;user&gt;\S+) from (?&lt;src_ip&gt;\d{1,3}(?:\.\d{1,3}){3})" | stats count AS attempts, dc(user) AS distinct_users, values(user) AS usernames by src_ip | sort - attempts</query>
          <earliest>-24h</earliest><latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>⚠ Successful Compromise (Failures + Success from same IP)</title>
      <table>
        <search>
          <query>index=main sourcetype=linux_secure ("Failed password" OR "Accepted password") | rex "Failed password for (?:invalid user )?(?&lt;f_user&gt;\S+) from (?&lt;src_ip&gt;\d{1,3}(?:\.\d{1,3}){3})" | rex "Accepted password for (?&lt;s_user&gt;\S+) from (?&lt;src_ip&gt;\d{1,3}(?:\.\d{1,3}){3})" | eval outcome=if(isnotnull(f_user),"failed","success") | stats count(eval(outcome="failed")) AS failures, count(eval(outcome="success")) AS successes, values(s_user) AS compromised_user by src_ip | where failures &gt;= 20 AND successes &gt;= 1</query>
          <earliest>-24h</earliest><latest>now</latest>
        </search>
        <format type="color" field="successes">
          <colorPalette type="list">[#DC4E41]</colorPalette>
        </format>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Post-Compromise sudo / Privilege Escalation</title>
      <table>
        <search>
          <query>index=main sourcetype=linux_secure "sudo:" "COMMAND=" | rex "sudo:\s+(?&lt;user&gt;\S+)\s+:.*USER=(?&lt;target_user&gt;\S+)\s+;\s+COMMAND=(?&lt;command&gt;.*)" | table _time, user, target_user, command | sort _time</query>
          <earliest>-24h</earliest><latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

> Note: in Simple XML the characters `<` `>` `&` inside queries are escaped as `&lt;` `&gt;` `&amp;`. That's why the regex `(?<src_ip>...)` appears as `(?&lt;src_ip&gt;...)`. It renders correctly in Splunk.

---

## Part C: Save the Detection as an Alert
1. Open the **Panel 4** search in the Search app.
2. **Save As → Alert.**
3. Configure:
   - **Title:** `SSH Brute Force - Successful Compromise`
   - **Alert type:** Scheduled → *Run every 5 minutes*, time range *last 5 minutes* (use Real-time for a live lab demo).
   - **Trigger condition:** *Number of Results* → *is greater than* → `0`.
   - **Trigger actions:** Add to Triggered Alerts, Severity = **High**. (In production you'd add email / webhook to a ticketing system.)
4. Save. Re-run Hydra (or re-upload the log) and confirm the alert appears under **Activity → Triggered Alerts** → screenshot.

---

## Evidence for the Portfolio
- [ ] Full dashboard populated with attack data
- [ ] Panel 4 showing the compromised IP + user in red
- [ ] Alert configuration screen
- [ ] Triggered Alerts list showing the fired alert

## Interview Line
> "I visualized the detection in a Splunk dashboard, a timechart to see the brute-force burst, a bar chart of top source IPs, and the key panel that correlates failures with successful logins to surface the compromised account. Then I saved that correlation as a scheduled alert triggering on any result, so in a real SOC it would page the on-call analyst the moment an attacker's brute force actually succeeds, not just when they're knocking."
