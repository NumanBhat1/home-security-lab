# Splunk From Zero: Complete Beginner Walkthrough

You have never opened Splunk. This guide assumes that. Every click, every menu, every button is spelled out. Follow it top to bottom and by the end you'll have data indexed, a search running, a dashboard built, and an alert saved. Take a screenshot at every ✅ CHECKPOINT, those are your portfolio evidence.

---

## 0. What Splunk Actually Is (60-second mental model)
Splunk is a search engine for logs. You feed it text log files. It chops each file into individual **events** (usually one line = one event), stamps each with a time, and stores them in a bucket called an **index**. Then you search across those events with a query language called **SPL** (Search Processing Language). That's the whole game: *get data into an index → search the index → visualize/alert on the results.*

Three words you'll see constantly:
- **Index** = the storage bucket your data lives in (like a database table). We'll make one called `linux`.
- **Sourcetype** = a label telling Splunk what *kind* of data this is, so it parses timestamps/fields correctly. For Linux auth logs the built-in one is `linux_secure`.
- **Search** = your SPL query. It always starts by naming the index, e.g. `index=linux`.

---

## 1. Open Splunk & Log In
1. Splunk Enterprise runs as a local web server on your machine. Open your browser and go to:
   **`http://localhost:8000`**
   (If that doesn't load, Splunk isn't running, see the "If Splunk won't start" box at the bottom.)
2. Log in with the admin username and password you set during installation. (Default username is `admin`; the password is whatever you chose when you first installed, Splunk forces you to set one.)
3. You land on the **Splunk Home** screen. You'll see a top menu bar and a panel of "Apps." The app you'll live in is **Search & Reporting**.

✅ **CHECKPOINT 1:** screenshot the Splunk Home screen.

---

## 2. Tour of the Screen (so nothing feels foreign)
- **Top black bar:** on the left it says *splunk>*, and there are menus like **Apps**, and on the right **Settings**, **Activity**, **Messages**, and your username. **Settings** is where you configure everything (indexes, data inputs, users).
- **Apps:** an "app" in Splunk is just a workspace. **Search & Reporting** is the default one where you type searches. Click it to enter.
- Inside Search & Reporting you get sub-tabs near the top: **Search**, **Analytics**, **Datasets**, **Reports**, **Alerts**, **Dashboards**. You'll use **Search**, **Dashboards**, and **Alerts**.

You don't need to memorize this. Just know: **Settings (top right) = setup**, **Search & Reporting app = doing the work.**

---

## 3. Create Your Index (`linux`) by Hand
An index is where your data will be stored. We'll make a dedicated one so your project data is clean and separate.

1. In the top-right black bar, click **Settings**.
2. Under the **DATA** column, click **Indexes**.
3. You now see a table of existing indexes (main, history, _internal, etc.). Top-right of this page, click the green **New Index** button.
4. A form opens. Fill in only these:
   - **Index Name:** `linux`  (lowercase, no spaces)
   - **Index Data Type:** leave on **Events** (the default: this is for text logs; "Metrics" is for numeric data, not us).
   - Leave **Home Path / Cold Path / Thawed Path** blank: Splunk fills defaults.
   - **Max Size of Entire Index:** leave default (500 GB is fine).
   - Everything else: leave default.
5. Click **Save**.
6. Your new `linux` index now appears in the list.

✅ **CHECKPOINT 2:** screenshot the Indexes list showing `linux`.

> Why a custom index? In a real SOC you separate data sources into indexes for access control and performance. Saying "I created a dedicated index for my Linux telemetry" is a small but real detail that shows you understand Splunk architecture, not just the search bar.

---

## 4. Add Data: Upload the `auth.log` File
Now we put data into that index. We'll use the simplest method: a one-time file upload.

1. Top-right black bar → **Settings**.
2. Under the **DATA** column → click **Add Data**.
3. You get three big tiles: **Upload**, **Monitor**, **Forward**. Click **Upload** (this is "upload a file from my computer, one time").
4. **Select Source:** click the green **Select File** button and choose your `auth.log` (the sample I gave you, or your live `auth_capture.log` from the Hydra lab). Click **Next** (top-right).
5. **Set Source Type:** this screen previews your events and asks what kind of data this is.
   - On the left, there's a **Source type** dropdown. Click it, and in the search box type `linux_secure`. Select **linux_secure** (it's under the Operating System category).
   - The preview on the right should now show your events with a proper timestamp column on the left. If timestamps look right, you're good.
   - Click **Next**.
6. **Input Settings:** this is where you choose the index.
   - **App Context:** leave as *Search & Reporting*.
   - **Host:** leave the default (it'll use the filename or your machine name: fine for the lab).
   - **Index:** click the dropdown and select **linux** (the one you just created). *This is the important field: make sure it's `linux`, not `default`/`main`.*
   - Click **Review** (top-right).
7. **Review:** it summarizes your choices (Input Type: Uploaded File, Source type: linux_secure, Index: linux). Click **Submit**.
8. You'll see **"File has been uploaded successfully."** Click the green **Start Searching** button.

✅ **CHECKPOINT 3:** screenshot the "upload successful" screen.

> **Upload vs Monitor vs Forward**, for the interview: *Upload* = one-time file (what we did). *Monitor* = Splunk watches a file/folder on the same machine and ingests new lines automatically. *Forward* = a lightweight **Universal Forwarder** agent installed on a remote server ships its logs to Splunk. Real SOCs use forwarders; upload is fine for a portfolio lab.

---

## 5. Your First Search: Confirm the Data Landed
Clicking **Start Searching** dropped you into the **Search** tab with a query already filled in. Let's do it deliberately so you understand it.

1. You're in **Search & Reporting → Search**. There's a long search bar.
2. Clear it and type exactly:
   ```
   index=linux
   ```
3. To the **right** of the search bar is a **time range picker**, it probably says "Last 24 hours." Your sample log is dated 2026-07-30, so if that's more than 24h ago, you'll get zero results. Click the time picker and choose **All time** (safest for a lab). *This is the #1 beginner gotcha: data is there but the time range hides it.*
4. Click the green magnifying-glass **search** button (or press Enter).
5. You should see a list of events, around 288 for the sample log. Below the search bar, click the **Events** count and note it.

✅ **CHECKPOINT 4:** screenshot showing `index=linux` returning your events.

### Reading the results
- Each row is one event (one log line). The timestamp is on the left.
- On the far left is a **Fields** sidebar. Splunk auto-extracted fields like `host`, `source`, `sourcetype`. Click any field to see its values.

### A couple of practice searches (build intuition)
```
index=linux "Failed password"
```
→ only the failed-login events. Notice you can just put a quoted phrase to keyword-search.

```
index=linux "Accepted password"
```
→ only successful logins. You should see the one compromise (`msfadmin` from the attacker IP).

> **How SPL reads:** left to right, piped through `|` like a Unix pipe. `index=linux` picks the data, then each `| command` transforms it. You'll see `| stats`, `| rex`, `| timechart` next, same idea every time.

---

## 6. Run the Real Detection
Now paste the actual brute-force detection. Time range still **All time**.

```
index=linux sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| bin _time span=5m
| stats count AS failed_attempts, dc(user) AS users_targeted, values(user) AS usernames by _time, src_ip
| where failed_attempts >= 20
| sort - failed_attempts
```
What each line does, plainly:
- `index=... "Failed password"`: grab failed-login events.
- `| rex "..."`: a regex that pulls two new fields out of the raw text: `user` and `src_ip`.
- `| bin _time span=5m`: group events into 5-minute time buckets.
- `| stats count ... by _time, src_ip`: per IP per bucket, count attempts and distinct usernames.
- `| where failed_attempts >= 20`: keep only the noisy ones (real brute force).
- `| sort - failed_attempts`: biggest offender first.

Result: the attacker IP with ~140 attempts across several usernames.

✅ **CHECKPOINT 5:** screenshot this result.

Now the important one, **did they get in?**
```
index=linux sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "Failed password for (?:invalid user )?(?<f_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex "Accepted password for (?<s_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval outcome=if(isnotnull(f_user),"failed","success")
| stats count(eval(outcome="failed")) AS failures, count(eval(outcome="success")) AS successes, values(s_user) AS compromised_user by src_ip
| where failures >= 20 AND successes >= 1
```
Result: one row, the attacker IP, ~140 failures, 1 success, `compromised_user = msfadmin`. **That single row is your security incident.**

✅ **CHECKPOINT 6:** screenshot this, it's the centerpiece of the project.

---

## 7. Build the Dashboard
A dashboard is a saved page of panels (charts/tables). Two ways; do the guided way first.

### Guided way (one panel, to learn it)
1. Run this:
   ```
   index=linux sourcetype=linux_secure "Failed password"
   | timechart span=1m count AS failed_logins
   ```
2. Above the results, click the **Visualization** tab (next to *Events*/*Statistics*). Pick **Column Chart** from the chart-type dropdown.
3. Top-right, click **Save As → Dashboard Panel**.
4. In the dialog: choose **New**, **Dashboard Title:** `SSH Brute Force Detection`, **Panel Title:** `Failed Logins Over Time`, Permissions can stay Private. Click **Save**.
5. Click **View Dashboard**. You now have a dashboard with one panel.

### Fast way (all 5 panels at once)
Open the companion file **`03_Splunk_Dashboard_and_Alert.md`** → **Part B**. It has complete Simple XML. To use it:
1. Left menu / top tab **Dashboards** → your `SSH Brute Force Detection` dashboard → click **Edit** (top right) → click **Source** (the `</>` toggle).
2. Delete what's there, paste the XML from Part B, click **Save**.
3. All five panels render at once. (Make sure the XML's `index=main` is changed to `index=linux`, use your editor's find-replace before pasting, or edit after.)

✅ **CHECKPOINT 7:** screenshot the full dashboard populated with data.

---

## 8. Save the Detection as an Alert
An alert is a search that runs on a schedule and notifies you when it finds something.
1. Go to **Search**, paste the **success-after-failure** query from Section 6.
2. Top-right **Save As → Alert**.
3. Fill in:
   - **Title:** `SSH Brute Force - Successful Compromise`
   - **Alert type:** **Scheduled** → *Run on Cron Schedule* or the simple *Run every… 5 minutes*. (For a lab demo you can pick **Real-time**.)
   - **Trigger alert when:** **Number of Results** → **is Greater than** → `0`.
   - **Trigger Actions:** click **Add Actions → Add to Triggered Alerts**, set **Severity: High**.
4. Click **Save**.
5. To see it fire: re-upload the log or (if live-monitoring) re-run Hydra. Then top bar **Activity → Triggered Alerts**.

✅ **CHECKPOINT 8:** screenshot the alert config and the Triggered Alerts list.

---

## You're Done: What You Just Built
Data ingested into a custom index → SPL detection that finds the brute force → correlation that proves compromise → a dashboard → a scheduled alert. That is a complete, real SOC detection workflow. Pair these screenshots with `01_SSH_Brute_Force_Detection.md` and you have a finished portfolio project you can walk an interviewer through end to end.

---

## Troubleshooting

**Search returns 0 results.** 99% of the time it's the **time range picker**. Set it to **All time**. Also confirm the index name matches (`index=linux`) and that you selected the `linux` index during upload.

**`http://localhost:8000` won't load / Splunk isn't running.**
- Mac: open Terminal and run the Splunk start command from where you installed it, e.g. `/Applications/Splunk/bin/splunk start` (adjust path). Or if installed via the app, launch the Splunk Enterprise app.
- It'll print "The Splunk web interface is at http://localhost:8000". Then refresh the browser.

**Forgot admin password.** You can reset it via the CLI: `splunk edit user admin -password NEWPASS -auth admin:OLDPASS`, or use the documented password-reset (create a `user-seed.conf`) procedure. Easiest is to remember what you set at install.

**Timestamps look wrong / all events at "now."** You probably didn't set sourcetype to `linux_secure` during upload, so Splunk didn't parse the log's real timestamp. Re-upload and make sure sourcetype = `linux_secure` on the "Set Source Type" step.

**`rex` field not extracting.** Make sure you didn't change the regex quotes to smart-quotes when copying. Straight double quotes only.

---

## Glossary (quick reference)
- **Event**: one log entry/line.
- **Index**: storage bucket for events (`linux`).
- **Sourcetype**: data-format label (`linux_secure`).
- **Source**: the file/path the data came from.
- **Host**: machine the data is about.
- **SPL**: Splunk's search language.
- **Field**: a named value extracted from an event (`src_ip`, `user`).
- **`| rex`**: regex field extraction.
- **`| stats`**: aggregate (count, dc, values…) by a field.
- **`| timechart`**: aggregate over time for charts.
- **`| where`**: filter rows after aggregation.
- **Alert**: a scheduled search that notifies on a condition.
- **Universal Forwarder**: lightweight agent that ships logs from other machines into Splunk.
