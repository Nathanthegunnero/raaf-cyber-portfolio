"""Hybrid classical + PQC key exchange and signatures."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from artemis.pqc_backend import KemBackend, SigBackend, get_kem_backend, get_sig_backend


@dataclass(frozen=True)
class HybridKemMaterial:
    classical_public: bytes
    classical_secret: bytes
    pqc_public: bytes
    pqc_secret: bytes
    kem_algorithm: str
    kem_backend: str


@dataclass(frozen=True)
class HybridEncapResult:
    classical_ephemeral_public: bytes
    pqc_ciphertext: bytes
    shared_secret: bytes  # 32-byte HKDF output before session AEAD keying
    classical_shared: bytes
    pqc_shared: bytes
    kem_algorithm: str
    kem_backend: str


@dataclass(frozen=True)
class HybridSigMaterial:
    classical_public: bytes
    classical_secret: bytes
    pqc_public: bytes
    pqc_secret: bytes
    sig_algorithm: str
    sig_backend: str


@dataclass(frozen=True)
class HybridSignature:
    classical_signature: bytes
    pqc_signature: bytes
    sig_algorithm: str
    sig_backend: str


def _hkdf_combine(*parts: bytes, info: bytes, length: int = 32) -> bytes:
    ikm = b"|".join(parts)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


def generate_hybrid_kem(*, kem: KemBackend | None = None) -> HybridKemMaterial:
    kem = kem or get_kem_backend()
    classical_secret = x25519.X25519PrivateKey.generate()
    classical_public = classical_secret.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pqc_public, pqc_secret = kem.generate_keypair()
    return HybridKemMaterial(
        classical_public=classical_public,
        classical_secret=classical_secret.private_bytes_raw(),
        pqc_public=pqc_public,
        pqc_secret=pqc_secret,
        kem_algorithm=kem.algorithm,
        kem_backend=kem.backend_name,
    )


def encapsulate_hybrid(recipient: HybridKemMaterial, *, kem: KemBackend | None = None) -> HybridEncapResult:
    """Initiator encapsulates to recipient's hybrid public material."""
    kem = kem or get_kem_backend()
    eph = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PublicKey.from_public_bytes(recipient.classical_public)
    classical_shared = eph.exchange(peer)
    pqc_ciphertext, pqc_shared = kem.encapsulate(recipient.pqc_public)
    combined = _hkdf_combine(
        classical_shared,
        pqc_shared,
        info=b"artemis-hybrid-kem-v1",
    )
    return HybridEncapResult(
        classical_ephemeral_public=eph.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        pqc_ciphertext=pqc_ciphertext,
        shared_secret=combined,
        classical_shared=classical_shared,
        pqc_shared=pqc_shared,
        kem_algorithm=kem.algorithm,
        kem_backend=kem.backend_name,
    )


def decapsulate_hybrid(
    recipient: HybridKemMaterial,
    *,
    classical_ephemeral_public: bytes,
    pqc_ciphertext: bytes,
    kem: KemBackend | None = None,
) -> bytes:
    kem = kem or get_kem_backend()
    priv = x25519.X25519PrivateKey.from_private_bytes(recipient.classical_secret)
    peer = x25519.X25519PublicKey.from_public_bytes(classical_ephemeral_public)
    classical_shared = priv.exchange(peer)
    pqc_shared = kem.decapsulate(recipient.pqc_secret, pqc_ciphertext)
    return _hkdf_combine(
        classical_shared,
        pqc_shared,
        info=b"artemis-hybrid-kem-v1",
    )


def generate_hybrid_sig(*, sig: SigBackend | None = None) -> HybridSigMaterial:
    sig = sig or get_sig_backend()
    classical = ed25519.Ed25519PrivateKey.generate()
    pqc_public, pqc_secret = sig.generate_keypair()
    return HybridSigMaterial(
        classical_public=classical.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        classical_secret=classical.private_bytes_raw(),
        pqc_public=pqc_public,
        pqc_secret=pqc_secret,
        sig_algorithm=sig.algorithm,
        sig_backend=sig.backend_name,
    )


def sign_hybrid(material: HybridSigMaterial, message: bytes, *, sig: SigBackend | None = None) -> HybridSignature:
    sig = sig or get_sig_backend()
    classical = ed25519.Ed25519PrivateKey.from_private_bytes(material.classical_secret)
    classical_signature = classical.sign(message)
    pqc_signature = sig.sign(material.pqc_secret, message)
    return HybridSignature(
        classical_signature=classical_signature,
        pqc_signature=pqc_signature,
        sig_algorithm=sig.algorithm,
        sig_backend=sig.backend_name,
    )


def verify_hybrid(
    material: HybridSigMaterial,
    message: bytes,
    signature: HybridSignature,
    *,
    sig: SigBackend | None = None,
) -> bool:
    sig = sig or get_sig_backend()
    public = ed25519.Ed25519PublicKey.from_public_bytes(material.classical_public)
    try:
        public.verify(signature.classical_signature, message)
        classical_ok = True
    except Exception:  # noqa: BLE001
        classical_ok = False
    pqc_ok = sig.verify(material.pqc_public, message, signature.pqc_signature)
    return classical_ok and pqc_ok
