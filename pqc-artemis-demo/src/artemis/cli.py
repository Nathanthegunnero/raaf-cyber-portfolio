"""CLI for the lab-only Artemis PQC demo."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from artemis import __version__
from artemis.hybrid import (
    HybridKemMaterial,
    HybridSigMaterial,
    HybridSignature,
    decapsulate_hybrid,
    encapsulate_hybrid,
    generate_hybrid_kem,
    generate_hybrid_sig,
    sign_hybrid,
    verify_hybrid,
)
from artemis.pqc_backend import probe_liboqs
from artemis.session import decrypt, derive_session_key, encrypt

DEFAULT_MESSAGE = b"Artemis lab message - synthetic / educational only"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artemis",
        description=(
            "Lab-only post-quantum cryptography demo (Artemis). "
            "Hybrid X25519+ML-KEM and Ed25519+ML-DSA, then HKDF + AES-GCM. "
            "Educational only — not for production. Not official Defence material."
        ),
    )
    parser.add_argument("--version", action="version", version=f"artemis {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show whether liboqs/ML-KEM/ML-DSA are available")

    demo = sub.add_parser("demo", help="Run end-to-end hybrid KEX + AEAD + hybrid sign/verify")
    demo.add_argument(
        "--message",
        default=DEFAULT_MESSAGE.decode("utf-8"),
        help="Plaintext to protect (default: lab sample string)",
    )
    demo.add_argument(
        "--require-liboqs",
        action="store_true",
        help="Fail if liboqs is not available (default: educational fallback)",
    )

    return parser


def _cmd_status() -> int:
    ok, detail = probe_liboqs()
    print("Artemis PQC demo — backend status")
    print("=" * 40)
    print(f"liboqs available: {'yes' if ok else 'no'}")
    print(f"detail: {detail}")
    print()
    print("Algorithms (when liboqs is present):")
    print("  KEM:  ML-KEM-768 (FIPS 203; formerly Kyber768)")
    print("  SIG:  ML-DSA-65  (FIPS 204; formerly Dilithium3)")
    print("Classical always available via cryptography:")
    print("  X25519 (ECDH) + Ed25519 (signatures)")
    print("  HKDF-SHA256 + AES-256-GCM")
    if not ok:
        print()
        print("NOTE: running without liboqs uses a labelled DEMO-ONLY fallback")
        print("so the hybrid *pipeline* can still be shown. Install liboqs-python")
        print("(+ native liboqs) for real ML-KEM / ML-DSA.")
    print()
    print("Lab-only / educational. Not official RAAF, ADF, or ASD material.")
    return 0


def _cmd_demo(message: str, require_liboqs: bool) -> int:
    from artemis.pqc_backend import PqcUnavailableError, get_kem_backend, get_sig_backend

    try:
        kem = get_kem_backend(require_real=require_liboqs)
        sig = get_sig_backend(require_real=require_liboqs)
    except PqcUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ok, detail = probe_liboqs()
    print("Artemis hybrid demo")
    print("=" * 40)
    print("LAB-ONLY / EDUCATIONAL — not for production")
    print(f"PQC backend: {kem.backend_name} ({detail})")
    print(f"KEM: {kem.algorithm}")
    print(f"SIG: {sig.algorithm}")
    print()

    recipient = generate_hybrid_kem(kem=kem)
    encap = encapsulate_hybrid(recipient, kem=kem)
    recovered = decapsulate_hybrid(
        recipient,
        classical_ephemeral_public=encap.classical_ephemeral_public,
        pqc_ciphertext=encap.pqc_ciphertext,
        kem=kem,
    )
    if recovered != encap.shared_secret:
        print("error: hybrid KEM shared secrets do not match", file=sys.stderr)
        return 1
    print("[OK] Hybrid KEX (X25519 + PQC KEM) — shared secrets match")
    print(f"     classical shared: {len(encap.classical_shared)} bytes")
    print(f"     PQC shared:       {len(encap.pqc_shared)} bytes")
    print(f"     combined (HKDF):  {len(encap.shared_secret)} bytes")

    session_key = derive_session_key(encap.shared_secret)
    plaintext = message.encode("utf-8")
    sealed = encrypt(session_key, plaintext)
    opened = decrypt(session_key, sealed)
    if opened != plaintext:
        print("error: AES-GCM round-trip failed", file=sys.stderr)
        return 1
    print("[OK] Session AEAD (HKDF → AES-256-GCM)")
    print(f"     plaintext:  {plaintext!r}")
    print(f"     ciphertext: {_b64(sealed.ciphertext)[:48]}… ({len(sealed.ciphertext)} bytes)")

    signer = generate_hybrid_sig(sig=sig)
    signature = sign_hybrid(signer, plaintext, sig=sig)
    if not verify_hybrid(signer, plaintext, signature, sig=sig):
        print("error: hybrid signature verify failed", file=sys.stderr)
        return 1
    if verify_hybrid(signer, plaintext + b"x", signature, sig=sig):
        print("error: hybrid signature verified a tampered message", file=sys.stderr)
        return 1
    print("[OK] Hybrid signatures (Ed25519 + PQC SIG)")
    print(f"     classical sig: {len(signature.classical_signature)} bytes")
    print(f"     PQC sig:       {len(signature.pqc_signature)} bytes")
    print()
    print("Summary JSON")
    print(
        json.dumps(
            {
                "lab_only": True,
                "kem_backend": kem.backend_name,
                "kem_algorithm": kem.algorithm,
                "sig_backend": sig.backend_name,
                "sig_algorithm": sig.algorithm,
                "hybrid_kem_ok": True,
                "aead_ok": True,
                "hybrid_sig_ok": True,
                "message_b64": _b64(plaintext),
                "ciphertext_b64": _b64(sealed.ciphertext),
            },
            indent=2,
        )
    )
    print()
    print("Disclaimer: personal educational portfolio. Not official RAAF/ADF/ASD material.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "status":
        return _cmd_status()
    if args.command == "demo":
        return _cmd_demo(args.message, args.require_liboqs)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
