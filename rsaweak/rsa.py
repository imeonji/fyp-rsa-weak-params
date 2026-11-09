"""Textbook RSA: key container, encrypt/decrypt, and key verification.

Textbook (unpadded) RSA is used on purpose: the project studies the
mathematics of the parameters, not padding schemes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .numtheory import modinv


@dataclass
class RSAKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    label: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def public(self) -> "PublicKey":
        return PublicKey(self.n, self.e)


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


def build_key(p: int, q: int, e: Optional[int] = None, d: Optional[int] = None, label: str = "") -> RSAKey:
    """Build an RSA key from p, q and either e or d."""
    n, phi = p * q, (p - 1) * (q - 1)
    if e is None and d is None:
        e = 65537
    if d is None:
        d = modinv(e, phi)
    if e is None:
        e = modinv(d, phi)
    return RSAKey(n=n, e=e, d=d, p=p, q=q, label=label)


def encrypt(m: int, pub: PublicKey) -> int:
    return pow(m, pub.e, pub.n)


def decrypt(c: int, n: int, d: int) -> int:
    return pow(c, d, n)


def verify_factors(n: int, p: int, q: int) -> bool:
    """True when p and q are a non-trivial factorisation of n."""
    return 1 < p < n and 1 < q < n and p * q == n


def private_key_from_factors(pub: PublicKey, p: int, q: int) -> int:
    """Once N is factored, d follows immediately: d = e^-1 mod (p-1)(q-1)."""
    return modinv(pub.e, (p - 1) * (q - 1))


def roundtrip_ok(pub: PublicKey, d: int, m: int = 0x46595020525341) -> bool:
    """Encrypt a test message with the public key and decrypt with a
    recovered d. Used to prove an attack really recovered a working key."""
    m %= pub.n
    return decrypt(encrypt(m, pub), pub.n, d) == m
