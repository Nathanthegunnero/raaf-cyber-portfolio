# Essential Eight Checker

Lab-only Python auditor: **synthetic host evidence → per-strategy maturity 0–3 → overall score (minimum of the eight)**.

Personal educational project by Nathan (Perth, WA) for Information Warfare Officer preparation. It demonstrates how a defender scores a host evidence pack against the public ACSC Essential Eight — not how to attack a network. **Not official RAAF, ADF, or ASD material. No Defence branding.**

This is a **simplified lab model**. It does not replace an ASD Essential Eight assessment.

---

## How to run

Python 3.11+ and PyYAML. From this directory:

```bash
python3 -m pip install -e .
python3 -m e8check list-controls
python3 -m e8check run --evidence samples/lab_ml1.json
python3 -m e8check run --evidence samples/lab_gaps.json
python3 -m e8check report --evidence samples/lab_ml1.json --out ./out
```

Without installing:

```bash
python3 -m pip install -r requirements.txt
PYTHONPATH=src python3 -m e8check run --evidence samples/lab_ml1.json
```

| Command | What it does |
|---------|----------------|
| `e8check run` | Evaluate one pack, print a console report. Add `--out DIR` to write JSON + Markdown |
| `e8check list-controls` | Print every loaded control id (E8-01 … E8-08) |
| `e8check report` | Same as `run`, but always writes `e8-report.json` and `e8-report.md` (default `./out`) |

Flags: `--evidence PATH` (default `samples/lab_ml1.json`), `--controls DIR` (default `controls/`), `--target N` (gap threshold, default `1`).

```bash
python3 -m pytest -q
```

---

## What a report looks like

```
Essential Eight Checker — Lab Report
=====================================
LAB-ONLY / SYNTHETIC EVIDENCE — personal educational portfolio, not official Defence material
Simplified lab model. This does not replace an ASD Essential Eight assessment.

Host:      WS-LAB-E8-01
OS:        Windows 11
Overall maturity:  ML1
  ACSC-style roll-up: overall maturity = minimum of the eight strategies
  (you are only as mature as your weakest strategy)
Target:            ML1
Gaps below target: 0

ID      Strategy                                    ML   ISM      Notes
E8-01   Application control                         1    Protect  Application control is not in enforce mode
E8-02   Patch applications                          1    Protect  Other applications are not current
E8-07   Multi-factor authentication                 1    Protect  MFA is not enabled for administrators
E8-08   Regular backups                             1    Protect  No offline or immutable backup copy is recorded
```

`samples/lab_gaps.json` is a synthetic host with obvious gaps and should print **Overall maturity: ML0**.

---

## Scoring

- Each strategy is scored **0, 1, 2, or 3**.
- **Overall maturity = the minimum of the eight.** That is the ACSC-style roll-up: you are only as mature as your weakest strategy.
- Gaps are strategies below `--target` (default 1).
- If a required evidence field is missing, that strategy is **ML0** and the finding says `insufficient evidence`.

### What ML1 / ML2 / ML3 mean *in this checker*

Honest lab model inspired by public ACSC intent. **Not** a verbatim ISM extract and **not** an official ASD assessor.

| ID | Strategy | ML1 (basic) | ML2 (tightened) | ML3 (stronger) |
|----|----------|-------------|-----------------|----------------|
| E8-01 | Application control | Enabled (audit or enforce) | Enforce + unsigned code blocked | + drivers and scripts in scope |
| E8-02 | Patch applications | Office + browser current; critical backlog ≤ 14 days | + other apps current; backlog ≤ 7 days | backlog ≤ 2 days |
| E8-03 | Patch operating systems | OS current; auto-update on; last patch ≤ 14 days | last patch ≤ 7 days | last patch ≤ 2 days |
| E8-04 | Restrict administrative privileges | Separate admin accounts; privilege use logged; ≤ 3 local admins | + MFA on administrative use | ≤ 1 local admin |
| E8-05 | Configure Microsoft Office macro settings | Internet macros blocked | + unsigned macros blocked | + trusted locations locked |
| E8-06 | User application hardening | Ads blocked; Java and Flash disabled | + web browser hardening | + Office OLE disabled |
| E8-07 | Multi-factor authentication | MFA for remote access | + MFA for administrators | + phishing-resistant MFA |
| E8-08 | Regular backups | Enabled; frequency ≤ 7 days | + offline or immutable copy | + restore tested |

ML0 = control absent, failing, or insufficient evidence.

---

## Evidence pack schema

A JSON object the checker evaluates. Keep packs **synthetic** and labelled.

```json
{
  "synthetic": true,
  "host": "WS-LAB-E8-01",
  "os": "Windows 11",
  "collected_at": "2026-08-15T02:00:00Z",
  "application_control": {
    "enabled": true,
    "mode": "audit",
    "unsigned_blocked": false,
    "drivers_controlled": false,
    "scripts_controlled": false
  },
  "patch_applications": {
    "office_current": true,
    "browser_current": true,
    "other_apps_current": false,
    "critical_unpatched_days_max": 14
  },
  "patch_os": {
    "os_current": true,
    "days_since_last_patch": 10,
    "auto_update": true
  },
  "admin_privileges": {
    "local_admin_count": 2,
    "admin_mfa": false,
    "separate_admin_accounts": true,
    "priv_use_logged": true
  },
  "office_macros": {
    "internet_macros_blocked": true,
    "unsigned_macros_blocked": false,
    "trusted_locations_locked": false
  },
  "app_hardening": {
    "ads_blocked": true,
    "java_disabled": true,
    "flash_disabled": true,
    "office_ole_disabled": false,
    "web_browser_hardening": true
  },
  "mfa": {
    "enabled_for_remote": true,
    "enabled_for_admins": false,
    "phishing_resistant": false
  },
  "backups": {
    "enabled": true,
    "offline_or_immutable": false,
    "tested_restore": false,
    "frequency_days": 7
  }
}
```

See `samples/README.md`.

---

## Lab-only disclaimer

- Defensive and educational. No exploits, payloads, C2, or attack procedures.
- Sample evidence is **hand-written and labelled** (`synthetic: true`). It is not from any real host or person.
- Framework names (ASD Essential Eight, ISM) are used as **public** alignment references only.
- This repository does not represent the RAAF, ADF, ASD, or any Defence organisation.
- **This does not replace an ASD assessment.**

See `samples/README.md` and `BUILD_LOG.md`.
