# Post-Quantum Cryptography Demo (Artemis)

Lab-only Python CLI: **hybrid key exchange (X25519 + ML-KEM/Kyber)**, **hybrid signatures (Ed25519 + ML-DSA/Dilithium)**, then **HKDF → AES-GCM** for a sample message.

Personal educational project by Nathan (Perth, WA) for Information Warfare Officer preparation. Demonstrates why defenders care about post-quantum migration — not how to break cryptography. **Not official RAAF, ADF, or ASD material. No Defence branding.**

Educational only. **Not for production.**

---

## Why this exists (harvest-now, decrypt-later)

A cryptographically relevant quantum computer (CRQC) would break widely used public-key algorithms (RSA, ECDH, ECDSA). Adversaries can **record ciphertext today** and decrypt it later when a CRQC exists — the “harvest now, decrypt later” threat. Data with a long confidentiality lifetime (government, Defence-adjacent, personal records) is already in scope.

NIST standardised:

| Role | NIST name | Older name | FIPS |
|------|-----------|------------|------|
| Key encapsulation | **ML-KEM** | Kyber | FIPS 203 |
| Digital signatures | **ML-DSA** | Dilithium | FIPS 204 |

This demo uses **ML-KEM-768** and **ML-DSA-65** when [liboqs](https://openquantumsafe.org/) / `liboqs-python` is available, combined with classical **X25519** and **Ed25519** (hybrid / PQ+T style).

### ASD / ISM guidance (plain words)

ASD’s public “Planning for post-quantum cryptography” guidance (and the ISM cryptography guidelines) tells organisations to **plan early**:

- By **end of 2026**: have a refined PQC transition plan (goals, risk, dependencies, data value).
- By **end of 2028**: start migrating critical systems / long-lived sensitive data.
- By **end of 2030**: cease traditional asymmetric primitives such as RSA / DH / ECDH / ECDSA in favour of ASD-approved PQC algorithms.

Hybrid (PQ + traditional) schemes can help interoperability during transition, but they are not the end state once a CRQC arrives. See: [Planning for post-quantum cryptography](https://www.cyber.gov.au/business-government/secure-design/quantum/planning-for-post-quantum-cryptography).

---

## How to run

Python 3.11+ and `cryptography`. Optional: `liboqs-python` (+ native liboqs) for real ML-KEM / ML-DSA.

```bash
python3 -m pip install -e ".[dev]"
# optional real PQC:
# python3 -m pip install "liboqs-python>=0.12"   # also needs native liboqs / cmake build

python3 -m artemis status
python3 -m artemis demo
python3 -m artemis demo --message "hello from the lab"
python3 -m pytest -q
```

Without installing:

```bash
python3 -m pip install -r requirements.txt
PYTHONPATH=src python3 -m artemis demo
```

| Command | What it does |
|---------|----------------|
| `artemis status` | Report whether liboqs / ML-KEM / ML-DSA are available |
| `artemis demo` | Hybrid KEX → HKDF session key → AES-GCM encrypt/decrypt → hybrid sign/verify |

If liboqs is missing, the demo uses a **labelled DEMO-ONLY fallback** so the hybrid *pipeline* still runs. Pass `--require-liboqs` to fail instead.

---

## What the demo shows

1. **Hybrid KEM**: X25519 ECDH shared secret concatenated (via HKDF) with an ML-KEM (or fallback) shared secret.
2. **Session AEAD**: HKDF-SHA256 → 256-bit key → AES-GCM seal/open of a sample message.
3. **Hybrid signatures**: Ed25519 + ML-DSA (or fallback); both must verify.

```
[OK] Hybrid KEX (X25519 + PQC KEM) — shared secrets match
[OK] Session AEAD (HKDF → AES-256-GCM)
[OK] Hybrid signatures (Ed25519 + PQC SIG)
```

---

## Limitations

- Educational / lab-only. **Do not use in production systems.**
- Fallback backends are **not** cryptographic KEMs/signatures; they only keep the pipeline demable without liboqs.
- Hybrid constructions here are a teaching sketch, not a protocol profile (no TLS, no certificates, no side-channel hardening).
- Not an ASD-approved product evaluation. Framework names are public alignment references only.
- This repository does not represent the RAAF, ADF, ASD, or any Defence organisation.

See `BUILD_LOG.md`.
