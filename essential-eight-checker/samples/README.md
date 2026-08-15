# Sample evidence packs (synthetic only)

**These files are entirely synthetic.** They were written by hand for this
checker. They are **not** captured from any real workstation, domain, or person.
They do not contain host inventories, usernames, or production data from any
machine.

- Every pack includes `"synthetic": true` and a `label` that says so.
- Hosts use lab names only (`WS-LAB-E8-01`, `WS-LAB-E8-GAPS`).
- No account names are included.

| File | Purpose |
|------|---------|
| `lab_ml1.json` | Basic implementation intended to score **about ML1 overall** (minimum of the eight) |
| `lab_gaps.json` | Obvious control gaps intended to score **ML0 overall** |

Do not replace these files with production evidence. This project is lab-only.
