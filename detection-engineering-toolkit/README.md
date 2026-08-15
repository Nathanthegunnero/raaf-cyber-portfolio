# Detection Engineering Toolkit

Lab-only Python rules engine: **synthetic logs → YAML detections → MITRE ATT&CK + ASD Essential Eight + ISM Detect/Respond**.

Personal educational project by Nathan (Perth, WA) for Information Warfare Officer preparation. It demonstrates how a defender writes, tests, and reports detections — not how to attack a network. **Not official RAAF or ADF material. No Defence branding.**

---

## How to run

Python 3.11+ and PyYAML. From this directory:

```bash
python3 -m pip install -e .
python3 -m deteng list-rules
python3 -m deteng run --logs samples/synthetic_events.jsonl
python3 -m deteng run --logs samples/clean_events.jsonl
python3 -m deteng report --logs samples/synthetic_events.jsonl --out ./out
```

Without installing:

```bash
python3 -m pip install -r requirements.txt
PYTHONPATH=src python3 -m deteng run --logs samples/synthetic_events.jsonl
```

| Command | What it does |
|---------|----------------|
| `deteng run` | Evaluate rules, print a console report. Add `--out DIR` to write JSON + Markdown |
| `deteng list-rules` | Print every loaded rule id, severity, and title |
| `deteng report` | Same as `run`, but always writes `detection-report.json` and `.md` (default `./out`) |

Flags: `--logs PATH` (default `samples/synthetic_events.jsonl`), `--rules DIR` (default `rules/`).

```bash
python3 -m pytest -q
```

---

## What a hit looks like

```
Detection Engineering Toolkit — Lab Report
============================================
LAB-ONLY / SYNTHETIC LOGS — personal educational portfolio, not official Defence material

Logs:    samples/synthetic_events.jsonl (17 events)
Rules:   8 evaluated
Hits:    8

[CRITICAL] DET-005  MFA disabled or bypass recorded
  MITRE: Defense Evasion / T1556.006 Modify Authentication Process: Multi-Factor Authentication
  Essential Eight: Multi-factor Authentication — treat MFA disable/bypass as a priority alert
  ISM: Detect
  Evidence: 1 event(s)  user=j.citizen, host=ID-LAB-01
  First: 2026-08-15T01:31:55Z  Last: 2026-08-15T01:31:55Z

[HIGH] DET-001  Failed logon burst
  MITRE: Credential Access / T1110 Brute Force
  Essential Eight: Multi-factor Authentication — MFA contains password-only stuffing against exposed accounts
  ISM: Detect
  Evidence: 5 event(s)  user=j.citizen, host=WS-LAB-01
```

`samples/clean_events.jsonl` is a benign baseline and should print **No detections**. It includes one failed logon (a typo) which sits below DET-001’s threshold of five failures in five minutes.

---

## ATT&CK + Essential Eight mapping

| Rule | Detection (evidence in the log) | ATT&CK | Essential Eight | ISM |
|------|----------------------------------|--------|-----------------|-----|
| DET-001 | Failed logon burst (threshold 5 / 5 min) | T1110 Brute Force | Multi-factor Authentication | Detect |
| DET-002 | New local admin / privilege assignment | T1098 Account Manipulation | Restrict Administrative Privileges | Detect |
| DET-003 | Scheduled task or service creation | T1053.005 Scheduled Task | Restrict Administrative Privileges | Detect |
| DET-004 | Workstation egress to a high dest port (≥ 49152) | T1571 Non-Standard Port | User Application Hardening | Detect |
| DET-005 | MFA disabled or bypass event | T1556.006 Modify Authentication Process | Multi-factor Authentication | Detect |
| DET-006 | PowerShell `-EncodedCommand` **log field** | T1059.001 PowerShell | Application Control | Detect |
| DET-007 | Logging stopped / audit log cleared | T1070.001 Clear Windows Event Logs | Regular Backups (evidence retention) | Detect |
| DET-008 | Cleartext FTP/Telnet from a workstation | T1040 Network Sniffing | User Application Hardening | Detect |

Conditions support field `equals` / `contains` / `regex`, numeric compares, a **threshold** (count in a time window, grouped by fields), and an optional **sequence** (e.g. failed then success from the same user).

---

## Lab-only disclaimer

- Defensive and educational. No exploits, payloads, C2, or attack procedures.
- Sample logs are **hand-written and labelled** (`synthetic: true`). They are not from any real network or person.
- Addresses are RFC 5737 documentation ranges and a fictional lab subnet.
- Framework names (MITRE ATT&CK, ASD Essential Eight, ISM) are used as **public** alignment references only.
- This repository does not represent the RAAF, ADF, or any Defence organisation.

See `samples/README.md` and `BUILD_LOG.md`.
