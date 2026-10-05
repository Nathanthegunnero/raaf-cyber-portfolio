# Build log

## 15 August 2026 — checker stood up

Stood up the Essential Eight Checker as original files for Nathan Hay’s personal Information Warfare Officer preparation portfolio (Perth, WA).

Shipped on this date:

- `e8check` package (`run`, `list-controls`, `report`)
- eight YAML controls (E8-01 … E8-08) with a simplified ML0–ML3 model
- synthetic lab_ml1 + lab_gaps evidence packs (hand-written, `synthetic: true`)
- pytest coverage for overall-minimum roll-up, both samples, and CLI report files

Not official RAAF, ADF, or ASD material. No production evidence. No secrets.
Overall maturity is the minimum of the eight strategies.

## 6 October 2026 — polish pass

Mentor-style polish (lab-only, still synthetic):

- README: clearer ASD Essential Eight Maturity Model wording (ML0–ML3 / tradecraft; same maturity across all eight; overall = minimum), public cyber.gov.au link, explicit “not Appendices A–C”
- Input validation: require `synthetic: true` (opt-out via `--allow-non-synthetic`); reject non-object evidence sections; require all eight strategies when loading controls
- Sample pack `lab_ml3.json` for an ML3 overall path in this simplified model
- GitHub Actions workflow running pytest + sample smoke on Python 3.11–3.13
- Extra edge-case tests (validation, ML3 sample, bad target, non-synthetic rejection)
- Version 0.1.1

Still not official RAAF/ADF/ASD material.
