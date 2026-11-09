"""Key generators: one honest generator and three deliberately weak ones.

Every generator takes a seeded random.Random so experiments are reproducible.
"""

from __future__ import annotations

import math
import random
from typing import List

from .numtheory import gcd, is_probable_prime, modinv, next_prime, random_prime
from .rsa import RSAKey, build_key


def standard_key(bits: int, rng: random.Random, e: int = 65537) -> RSAKey:
    """A normal RSA key: two independent random primes of bits/2 each."""
    half = bits // 2
    while True:
        p = random_prime(half, rng)
        q = random_prime(bits - half, rng)
        if p != q and gcd(e, (p - 1) * (q - 1)) == 1:
            return build_key(p, q, e=e, label="standard")


# ---------------------------------------------------------------------------
# Weakness 1: p and q too close together  ->  Fermat factorisation
# ---------------------------------------------------------------------------


def close_primes_key(bits: int, gap_bits: int, rng: random.Random, e: int = 65537) -> RSAKey:
    """p is a random prime of bits/2 bits and q is the next prime after
    p + delta, where delta is a random number of exactly `gap_bits` bits.

    So |p - q| is about 2^gap_bits. A real generator should make |p - q|
    about 2^(bits/2); FIPS 186-5 requires |p - q| > 2^(bits/2 - 100).
    """
    half = bits // 2
    if not 1 <= gap_bits < half - 2:
        raise ValueError("gap_bits must be between 1 and bits/2 - 3")
    while True:
        p = random_prime(half, rng)
        delta = rng.getrandbits(gap_bits) | (1 << (gap_bits - 1))
        q = next_prime(p + delta, rng=rng)
        if (p * q).bit_length() != bits:
            continue
        if gcd(e, (p - 1) * (q - 1)) == 1:
            key = build_key(p, q, e=e, label="close-primes")
            key.meta["gap_bits"] = gap_bits
            key.meta["diff"] = abs(p - q)
            return key


# ---------------------------------------------------------------------------
# Weakness 2: small private exponent d  ->  Wiener's attack
# ---------------------------------------------------------------------------


def balanced_primes(bits: int, rng: random.Random):
    """p, q of bits/2 bits each with q < p < 2q (Wiener's assumption)."""
    half = bits // 2
    while True:
        p = random_prime(half, rng)
        q = random_prime(half, rng)
        if p == q:
            continue
        p, q = max(p, q), min(p, q)
        if p < 2 * q and (p * q).bit_length() == bits:
            return p, q


def small_d_key(bits: int, d_bits: int, rng: random.Random) -> RSAKey:
    """Choose d first (a random odd number of exactly d_bits bits) and derive
    e = d^-1 mod phi(N). Wiener's bound says the attack works when
    d < N^(1/4) / 3, i.e. roughly d_bits < bits/4 - 1.58.
    """
    p, q = balanced_primes(bits, rng)
    phi = (p - 1) * (q - 1)
    while True:
        d = rng.getrandbits(d_bits) | (1 << (d_bits - 1)) | 1
        if gcd(d, phi) == 1:
            break
    key = build_key(p, q, d=d, label="small-d")
    key.meta["d_bits"] = d_bits
    key.meta["wiener_bound_bits"] = math.log2(math.isqrt(math.isqrt(key.n)) / 3)
    return key


# ---------------------------------------------------------------------------
# Weakness 3: primes shared between moduli  ->  batch GCD
# ---------------------------------------------------------------------------


def shared_prime_keyset(count: int, bits: int, shared_pairs: int, rng: random.Random) -> List[RSAKey]:
    """`count` keys of which `shared_pairs` pairs reuse one prime.

    Models a device with a poor entropy source at boot time, which is the
    failure Heninger et al. found on the Internet in "Mining Your Ps and Qs"
    (USENIX Security 2012).
    """
    if 2 * shared_pairs > count:
        raise ValueError("need count >= 2 * shared_pairs")
    half = bits // 2
    keys: List[RSAKey] = []
    for i in range(shared_pairs):
        shared = random_prime(half, rng)
        for j in range(2):
            while True:
                other = random_prime(bits - half, rng)
                if other != shared and gcd(65537, (shared - 1) * (other - 1)) == 1:
                    break
            k = build_key(shared, other, e=65537, label="shared-prime")
            k.meta["pair"] = i
            keys.append(k)
    while len(keys) < count:
        keys.append(standard_key(bits, rng))
    rng.shuffle(keys)
    return keys
