"""Hybrid KEX, AEAD, and signature tests (pass with or without liboqs)."""

from __future__ import annotations

import pytest

from artemis.hybrid import (
    decapsulate_hybrid,
    encapsulate_hybrid,
    generate_hybrid_kem,
    generate_hybrid_sig,
    sign_hybrid,
    verify_hybrid,
)
from artemis.pqc_backend import FallbackKem, FallbackSig, probe_liboqs, get_kem_backend, get_sig_backend
from artemis.session import decrypt, derive_session_key, encrypt


def test_probe_liboqs_returns_tuple():
    ok, detail = probe_liboqs()
    assert isinstance(ok, bool)
    assert isinstance(detail, str)
    assert detail


def test_hybrid_kem_roundtrip_with_available_backend():
    kem = get_kem_backend()
    recipient = generate_hybrid_kem(kem=kem)
    encap = encapsulate_hybrid(recipient, kem=kem)
    recovered = decapsulate_hybrid(
        recipient,
        classical_ephemeral_public=encap.classical_ephemeral_public,
        pqc_ciphertext=encap.pqc_ciphertext,
        kem=kem,
    )
    assert recovered == encap.shared_secret
    assert len(recovered) == 32


def test_hybrid_kem_roundtrip_fallback_explicit():
    kem = FallbackKem()
    recipient = generate_hybrid_kem(kem=kem)
    encap = encapsulate_hybrid(recipient, kem=kem)
    recovered = decapsulate_hybrid(
        recipient,
        classical_ephemeral_public=encap.classical_ephemeral_public,
        pqc_ciphertext=encap.pqc_ciphertext,
        kem=kem,
    )
    assert recovered == encap.shared_secret


def test_session_aead_roundtrip():
    key = derive_session_key(b"x" * 32)
    sealed = encrypt(key, b"hello artemis")
    assert decrypt(key, sealed) == b"hello artemis"


def test_hybrid_sig_roundtrip():
    sig = get_sig_backend()
    material = generate_hybrid_sig(sig=sig)
    message = b"sign me"
    signature = sign_hybrid(material, message, sig=sig)
    assert verify_hybrid(material, message, signature, sig=sig) is True
    assert verify_hybrid(material, b"tampered", signature, sig=sig) is False


def test_hybrid_sig_fallback_explicit():
    sig = FallbackSig()
    material = generate_hybrid_sig(sig=sig)
    message = b"fallback"
    signature = sign_hybrid(material, message, sig=sig)
    assert verify_hybrid(material, message, signature, sig=sig) is True


@pytest.mark.skipif(not probe_liboqs()[0], reason="liboqs not available")
def test_real_liboqs_ml_kem_and_ml_dsa():
    kem = get_kem_backend(require_real=True)
    sig = get_sig_backend(require_real=True)
    assert kem.backend_name == "liboqs"
    assert sig.backend_name == "liboqs"
    assert "ML-KEM" in kem.algorithm
    assert "ML-DSA" in sig.algorithm
    recipient = generate_hybrid_kem(kem=kem)
    encap = encapsulate_hybrid(recipient, kem=kem)
    assert decapsulate_hybrid(
        recipient,
        classical_ephemeral_public=encap.classical_ephemeral_public,
        pqc_ciphertext=encap.pqc_ciphertext,
        kem=kem,
    ) == encap.shared_secret
    material = generate_hybrid_sig(sig=sig)
    signature = sign_hybrid(material, b"liboqs", sig=sig)
    assert verify_hybrid(material, b"liboqs", signature, sig=sig)
