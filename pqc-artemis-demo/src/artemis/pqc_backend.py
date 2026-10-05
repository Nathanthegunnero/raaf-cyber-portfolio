"""Optional liboqs (ML-KEM / ML-DSA) backend with clean fallback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class PqcUnavailableError(RuntimeError):
    """Raised when a real PQC backend is required but not available."""


@dataclass(frozen=True)
class KemResult:
    public_key: bytes
    ciphertext: bytes
    shared_secret: bytes
    algorithm: str
    backend: str


@dataclass(frozen=True)
class SigKeyPair:
    public_key: bytes
    secret_key: bytes
    algorithm: str
    backend: str


@dataclass(frozen=True)
class SignatureResult:
    signature: bytes
    algorithm: str
    backend: str


class KemBackend(Protocol):
    algorithm: str
    backend_name: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return shared_secret."""


class SigBackend(Protocol):
    algorithm: str
    backend_name: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


def probe_liboqs() -> tuple[bool, str]:
    """Return (available, detail)."""
    try:
        import oqs  # type: ignore

        kems = list(oqs.get_enabled_kem_mechanisms())
        sigs = list(oqs.get_enabled_sig_mechanisms())
        has_kem = "ML-KEM-768" in kems
        has_sig = "ML-DSA-65" in sigs
        if has_kem and has_sig:
            return True, f"liboqs-python OK (ML-KEM-768, ML-DSA-65)"
        return False, f"liboqs loaded but missing mechanisms (kems={has_kem}, sigs={has_sig})"
    except Exception as exc:  # noqa: BLE001 — intentional probe
        return False, f"liboqs unavailable: {exc}"


class LiboqsKem:
    algorithm = "ML-KEM-768"
    backend_name = "liboqs"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        import oqs  # type: ignore

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        import oqs  # type: ignore

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared = kem.encap_secret(public_key)
            return ciphertext, shared

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        import oqs  # type: ignore

        with oqs.KeyEncapsulation(self.algorithm, secret_key) as kem:
            return kem.decap_secret(ciphertext)


class LiboqsSig:
    algorithm = "ML-DSA-65"
    backend_name = "liboqs"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        import oqs  # type: ignore

        with oqs.Signature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        import oqs  # type: ignore

        with oqs.Signature(self.algorithm, secret_key) as sig:
            return sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        import oqs  # type: ignore

        with oqs.Signature(self.algorithm) as sig:
            return bool(sig.verify(message, signature, public_key))


class FallbackKem:
    """Educational stand-in when liboqs is missing.

    NOT a real KEM. Uses OS randomness + SHA-256 so the hybrid *pipeline*
    can still be demonstrated. Ciphertexts are labelled and tests that need
    real PQC should skip when this backend is selected.
    """

    algorithm = "DEMO-ONLY-KEM (not ML-KEM)"
    backend_name = "fallback"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.hashes import Hash, SHA256
        import os

        secret_key = os.urandom(32)
        digest = Hash(SHA256())
        digest.update(b"artemis-demo-kem-pk|")
        digest.update(secret_key)
        return digest.finalize(), secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.hashes import Hash, SHA256
        import os

        ephemeral = os.urandom(32)
        digest = Hash(SHA256())
        digest.update(b"artemis-demo-kem-ss|")
        digest.update(public_key)
        digest.update(ephemeral)
        shared = digest.finalize()
        ciphertext = b"DEMO-KEM|" + ephemeral
        return ciphertext, shared

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.hashes import Hash, SHA256

        if not ciphertext.startswith(b"DEMO-KEM|"):
            raise ValueError("fallback KEM expected DEMO-KEM| ciphertext")
        ephemeral = ciphertext[len(b"DEMO-KEM|") :]
        digest_pk = Hash(SHA256())
        digest_pk.update(b"artemis-demo-kem-pk|")
        digest_pk.update(secret_key)
        public_key = digest_pk.finalize()
        digest = Hash(SHA256())
        digest.update(b"artemis-demo-kem-ss|")
        digest.update(public_key)
        digest.update(ephemeral)
        return digest.finalize()


class FallbackSig:
    """Educational stand-in when liboqs is missing. NOT a real signature scheme.

    Stores the full secret inside the "public" key blob so verify can recompute
    an HMAC-style tag. This is deliberately insecure and labelled DEMO-ONLY.
    """

    algorithm = "DEMO-ONLY-SIG (not ML-DSA)"
    backend_name = "fallback"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        import os

        secret_key = os.urandom(32)
        public_key = b"DEMO-SIG-PK|" + secret_key  # insecure on purpose
        return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives.hashes import Hash, SHA256

        digest = Hash(SHA256())
        digest.update(b"artemis-demo-sig|")
        digest.update(secret_key)
        digest.update(message)
        return b"DEMO-SIG|" + digest.finalize()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not public_key.startswith(b"DEMO-SIG-PK|"):
            return False
        if not signature.startswith(b"DEMO-SIG|"):
            return False
        secret_key = public_key[len(b"DEMO-SIG-PK|") :]
        expected = self.sign(secret_key, message)
        return expected == signature


def get_kem_backend(*, require_real: bool = False) -> KemBackend:
    ok, detail = probe_liboqs()
    if ok:
        return LiboqsKem()
    if require_real:
        raise PqcUnavailableError(detail)
    return FallbackKem()


def get_sig_backend(*, require_real: bool = False) -> SigBackend:
    ok, detail = probe_liboqs()
    if ok:
        return LiboqsSig()
    if require_real:
        raise PqcUnavailableError(detail)
    return FallbackSig()
