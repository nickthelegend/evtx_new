# evtx_new — Windows Log Collector & Sigma Threat Hunter

> A Windows endpoint agent that continuously collects Event Logs, hunts for threats with Chainsaw + Sigma rules, and ships the findings to a backend API.

## Overview

`evtx_new` is a Python agent that runs on Windows hosts to automate security-log
collection and detection. On a fixed cycle it pulls records from the native Windows
Event Log (Security / System / Application), exports them to JSON, XML, and `.evtx`,
and then runs the bundled [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
binary over the captured `.evtx` file using a library of Sigma rules to flag
suspicious activity. Collected events and any detections are uploaded to a backend
API (and optionally emailed), making it the endpoint half of a lightweight
log-management / SIEM-style pipeline.

The repository contains several iterations of the collector plus the assets needed
to package it into a single standalone Windows executable.

## Features

- **Windows Event Log collection** via `pywin32` (`win32evtlog`) — reads Security,
  System, and Application logs and normalizes each event (EventID, timestamp,
  source, type, category, formatted message).
- **Multi-format export** — writes events to JSON and XML, and snapshots the raw
  channel to `.evtx` using `wevtutil epl`.
- **Sigma-based threat hunting** — invokes `chainsaw.exe hunt` against the captured
  `.evtx` file with the bundled Sigma rule set (127 `win_security_*` rules under
  `needed/`) and the Chainsaw event-log mappings in `mappings/`.
- **Backend integration** — POSTs collected logs and Chainsaw detections to an API
  endpoint, tagged with an access key, the host's local IP, and its hostname; can
  also trigger an email report of the findings.
- **Continuous operation** — runs in a loop aligned to a recurring interval so the
  host is monitored on an ongoing basis.
- **Single-file distribution** — a PyInstaller spec (`evtx.spec`) bundles the script,
  `chainsaw.exe`, the Sigma rules, and mappings into one `evtx.exe` that requests
  UAC elevation (required to read the Security log).

## Tech Stack

- **Language:** Python 3
- **Windows APIs:** `pywin32` (`win32evtlog`, `win32evtlogutil`, `win32security`),
  `wevtutil`
- **HTTP:** `requests`
- **Threat detection:** [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
  (bundled `chainsaw.exe`) + Sigma rules
- **Packaging:** PyInstaller (`evtx.spec` → `evtx.exe`)

> Note: this agent uses the native Windows Event Log APIs and must be run on
> Windows, with Administrator privileges to access the Security channel.

## Getting Started

### Prerequisites
- Windows with Administrator access
- Python 3.x

### Install dependencies
```bash
pip install pywin32 requests
```

### Run the collector

The primary entry point is `evtx.py`, which collects Security logs, runs Chainsaw,
and uploads results. It takes an API access key and a report email:

```bash
python evtx.py --access-key <YOUR_ACCESS_KEY> --email you@example.com
```

`main.py` is a standalone variant that only collects System/Security/Application
logs and writes them to local `json/`, `xml/`, and `evtx/` folders (no API upload):

```bash
python main.py
```

### Build the standalone executable
```bash
pip install pyinstaller
pyinstaller evtx.spec
# produces dist/evtx.exe (bundles chainsaw.exe, Sigma rules, and mappings)
```

The API endpoints are configured at the top of the scripts (e.g. `API_ENDPOINT`,
`CHAINSAW_ENDPOINT`) and default to a local backend on `http://localhost:3001`.

## Project Structure

```
evtx_new/
├── evtx.py          # Main agent: collect Security logs → Chainsaw → upload + email
├── final.py         # Earlier full-pipeline variant (collect → Chainsaw → upload)
├── main.py          # Standalone multi-channel collector (JSON/XML/EVTX, no upload)
├── evtx.spec        # PyInstaller build spec (bundles binary + rules → evtx.exe)
├── chainsaw.exe     # Bundled Chainsaw threat-hunting binary
├── needed/          # Sigma rule set (win_security_* .yml rules)
├── mappings/        # Chainsaw event-log field mappings
├── output/          # Chainsaw detection results (JSON)
└── dist/            # PyInstaller build output
```

---

Built by [nickthelegend](https://github.com/nickthelegend) · [nickthelegend.tech](https://nickthelegend.tech)
