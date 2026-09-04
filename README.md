# Browser Session Forensics Tool

**A real, no-mock-data Firefox `sessionstore.jsonlz4` forensic parser — CLI + Web App.**
Parses real Firefox session-restore files (real `mozLz4a` magic header, real LZ4-block decompression, real JSON) to surface cleartext credentials leaked in browsing-session URLs, webmail/cloud-storage/file-sharing access, paste-site/anonymous-file-host access, abnormal tab-repetition patterns, and recently-closed-tab evidence — by inspecting live decompressed session data on the machine it runs on.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, digital-forensics, and incident-response purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against systems, media, or files that you own or for which you have explicit, documented authorization to investigate. Analyzing browser artifacts without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), organizational policy, and/or an individual's privacy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, mishandled evidence, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not a substitute** for a certified digital-forensics suite, a validated forensic workflow with documented chain of custody, or a qualified forensic examiner's expert testimony in legal proceedings. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a session file is free of sensitive or exfiltration-relevant activity. This tool checks a specific, limited set of URL- and structure-based patterns only.
- **Read-only by design.** The Security Engine only reads bytes from the target session file(s) — it never modifies, deletes, or writes back to any file it parses. Verify this yourself by reading `app/security_engine/__init__.py` before running it on evidence you care about (and always work from a copy, never the original evidence, per standard forensic practice).
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given browser profile or session file, **do not run this tool against it.**

---

## Scope: Firefox `sessionstore.jsonlz4` only (honest about limits)

This version targets **Firefox's `sessionstore.jsonlz4` format specifically** — the real, documented, LZ4-block-compressed JSON file Firefox writes to `<profile>/sessionstore.jsonlz4` and `<profile>/sessionstore-backups/*.jsonlz4`/`*.baklz4` to support session restore. Every byte this tool decompresses and every JSON field it reads comes from that real format.

**Out of scope (documented, not silently ignored):**
- **Chrome / Chromium's SNSS session format** (`Current Session`, `Current Tabs`, `Last Session` files under `<profile>/Sessions/`) uses a completely different binary protobuf-style command-log encoding, not LZ4-compressed JSON. Supporting it is a **future/out-of-scope item** for this tool — do not point it at Chrome profile data expecting results.
- Any file that doesn't start with the real `mozLz4a\x00` magic header is reported as a **BSF-006 "unrecognized session format"** finding rather than silently skipped or (worse) guessed at.

---

## Who should use this project

- Digital forensic examiners and incident responders triaging a Firefox profile for evidence of credential exposure, data exfiltration, or recent browsing activity.
- Security students and self-learners studying browser-artifact forensics and the real Firefox `sessionstore.jsonlz4` file format.
- SOC analysts who need a quick, scriptable first pass over a captured/copied Firefox profile before deeper analysis.
- CI/CD or automated evidence-intake pipelines that want a scan gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from actually decompressing and JSON-decoding a real `sessionstore.jsonlz4` file. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented, pure Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/evidence-intake scripts) and the web app (for case dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite + the `lz4` library, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
browser-session-forensics-tool/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real sessionstore.jsonlz4 parser (mozLz4a header + lz4.block + json)
│   ├── detection_rules/      # 6 documented detection rules (BSF-001..006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real constructed sessionstore.jsonlz4 files, nothing mocked
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| BSF-001 | Cleartext Credentials in Session URL | Medium | A parsed tab-entry URL is `http://` (not https) **and** contains a query param name like `password=`, `token=`, `api_key=`, `session=`, or `auth=` |
| BSF-002 | Webmail / Cloud-Storage Access | Medium | A parsed tab-entry URL's hostname matches a common webmail/cloud-storage/file-sharing service (`mail.google.com`, `outlook.office.com`, `drive.google.com`, `dropbox.com`, `wetransfer.com`, `mega.nz`) |
| BSF-003 | Excessive URL Repetition Across Tabs | Low | The same URL appears across 10+ distinct tabs/entries in one session file — automated/scripted-browsing or tab-bombing anomaly |
| BSF-004 | Recently Closed Tab Evidence | Low / informational | `closedWindows`/`_closedTabs` data contains URLs not present among currently-open tabs — leftover session-restore evidence worth independent review |
| BSF-005 | Paste-Site / Anonymous File-Host Access | Medium | A parsed tab-entry URL matches a known paste-site/anonymous-file-host domain (`pastebin.com`, `paste.ee`, `anonfiles.com`, `transfer.sh`, `ngrok.io`) — potential data-staging/exfil or C2 delivery channel |
| BSF-006 | Unrecognized Session File Format | Low / informational | The file's leading bytes did not match the real `mozLz4a\x00` magic header — parse-note, not a crash |

---

## Setup & Run

### Requirements
- Python 3.9+
- The `lz4` package (real LZ4-block decompression of `sessionstore.jsonlz4` payloads — see `requirements.txt`)

### Install

```bash
git clone <this-repository-url>
cd browser-session-forensics-tool
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
BSF_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/bsf.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/sessionstore.jsonlz4
python3 cli/main.py scan ~/.mozilla/firefox/<profile> --json
python3 cli/main.py scan ~/.mozilla/firefox/<profile> --csv findings.csv
python3 cli/main.py rules
```

The `scan` target can be a single `sessionstore.jsonlz4`/`.baklz4` file, or a directory (such as a copied Firefox profile folder) that the engine will walk — including its `sessionstore-backups/` subfolder — for any file that looks like a session-store file. The CLI exits with status code `1` if any findings are detected (useful as a CI/evidence-intake gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite includes pure rule-level unit tests against synthetic context dicts, plus engine-level tests that **build a real, spec-conformant `sessionstore.jsonlz4` file from scratch** (real JSON matching Firefox's schema, real `lz4.block.compress`, real `mozLz4a` magic header + real 4-byte size header written to a real temp file) and run the actual `ScanEngine` against it — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Browser Session Forensics Tool check?**
It real-parses a Firefox `sessionstore.jsonlz4` (or `.baklz4`) file — real `mozLz4a` magic header check, real LZ4-block decompression, real JSON decode — and flags cleartext credentials in tab URLs, webmail/cloud-storage/paste-site access, abnormal URL repetition across tabs, and recently-closed-tab evidence.

**Who should use it?**
Digital forensic examiners, incident responders, and security students analyzing Firefox browser artifacts on systems, media, or files they own or are explicitly authorized to investigate.

**Is it a replacement for a professional security audit or certified forensic tool?**
No. It is an educational and productivity aid only — see the Disclaimer section above. It is not a substitute for certified forensic suites, documented chain-of-custody procedures, or expert testimony.

**Does it support Chrome or other browsers?**
Not in this version. It targets Firefox's `sessionstore.jsonlz4` format specifically. Chrome's SNSS session format (`Current Session`/`Current Tabs` under `Sessions/`) uses a different binary encoding and is a documented future/out-of-scope item.

**Does it modify my evidence files?**
No. It only reads bytes from the session file(s) it's pointed at via `open(path, "rb")`. It never writes to, deletes, or changes the files it parses. Always work from a forensic copy, not original evidence.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
