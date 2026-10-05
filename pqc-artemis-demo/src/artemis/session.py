"""Derive an AEAD session key (HKDF) and encrypt/decrypt with AES-GCM."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class SealedMessage:
    nonce: bytes
    ciphertext: bytes
    aad: bytes


def derive_session_key(shared_secret: bytes, *, context: bytes = b"artemis-session-v1") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)


def encrypt(session_key: bytes, plaintext: bytes, *, aad: bytes = b"artemis-lab") -> SealedMessage:
    nonce = os.urandom(12)
    aes = AESGCM(session_key)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return SealedMessage(nonce=nonce, ciphertext=ciphertext, aad=aad)


def decrypt(session_key: bytes, sealed: SealedMessage) -> bytes:
    aes = AESGCM(session_key)
    return aes.decrypt(sealed.nonce, sealed.ciphertext, sealed.aad)
