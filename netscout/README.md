# NetScout — Network Vulnerability Scanner

A web-based network vulnerability scanner with a clean frontend and Python backend.

---

## What It Does

- **Port Scanning** — Scans 44 commonly targeted TCP ports on any IP or IP range
- **Service Detection** — Identifies what service is running on each port (FTP, SSH, HTTP, MySQL, etc.)
- **Banner Grabbing** — Tries to grab service version info from open ports
- **Vulnerability Matching** — Matches each open port to known vulnerabilities from the built-in database
- **CVE References** — Links to real CVE entries on the NVD database
- **Risk Scoring** — Assigns CRITICAL / HIGH / MEDIUM / LOW / INFO risk levels
- **Full Report** — Generates a professional HTML report you can print or save as PDF

---

## How to Set Up

### Step 1 — Install Python
Make sure Python 3.8 or newer is installed.
Download from: https://www.python.org/downloads/

### Step 2 — Install Flask
Open your terminal (Command Prompt on Windows), go to the netscout folder, and run:

```
pip install -r requirements.txt
```

### Step 3 — Run the App

```
python app.py
```

### Step 4 — Open in Browser

Open your browser and go to:

```
http://127.0.0.1:5000
```

---

## How to Use

1. Enter an IP address: `192.168.1.1`
2. Or enter a range: `192.168.1.0/24`
3. Click **Scan**
4. Wait 30–60 seconds for the scan to complete
5. View the full vulnerability report
6. Click **Print / Save as PDF** to save your report

---

## Important Notice

> Only scan systems you **own** or have **written permission** to test.
> Unauthorized scanning is illegal in most countries.

---

## Project Structure

```
netscout/
├── app.py           ← Flask web server (start here)
├── scanner.py       ← Port scanning and service detection
├── vuln_db.py       ← Vulnerability database with CVE references
├── requirements.txt ← Python dependencies
├── templates/
│   ├── index.html   ← Scan input page
│   └── report.html  ← Results report page
└── README.md        ← This file
```
