# Sample logs (synthetic only)

**These files are entirely synthetic.** They were written by hand for this
toolkit. They are **not** captured from any real network, workstation, identity
platform, or person.

- Every JSON object includes `"synthetic": true`.
- Hosts use lab names (`WS-LAB-*`, `DC-LAB-*`).
- Addresses are documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) plus a fictional `10.20.30.0/24` lab subnet.
- Account names (`j.citizen`, `a.operator`, `k.reviewer`) are fictitious.

| File | Purpose |
|------|---------|
| `synthetic_events.jsonl` | Seeded evidence intended to fire DET-001 … DET-008 |
| `clean_events.jsonl` | Benign baseline intended to fire **no** rules |

`clean_events.jsonl` includes a **single** failed logon (a typed-password miss).
That is below DET-001’s threshold of five failures in five minutes and is an
expected non-hit.

Do not replace these files with production logs. This project is lab-only.
