# Build log

## 6 October 2026 — Artemis PQC demo stood up

Original files for Nathan Hay’s personal Information Warfare Officer preparation portfolio (Perth, WA).

Shipped:

- `artemis` CLI (`status`, `demo`)
- Hybrid KEX: X25519 + ML-KEM-768 (liboqs) with DEMO-ONLY fallback
- Hybrid signatures: Ed25519 + ML-DSA-65 (liboqs) with DEMO-ONLY fallback
- HKDF-SHA256 session key + AES-256-GCM sample encrypt/decrypt
- pytest coverage (always-on hybrid/AEAD tests + optional real-liboqs test)
- README covering harvest-now-decrypt-later, FIPS 203/204 names, ASD/ISM PQC timeline in plain words

Not official RAAF, ADF, or ASD material. Not for production.
