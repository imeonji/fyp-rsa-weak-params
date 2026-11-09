"""Number-theory primitives used by RSA and the attacks.

Everything here is written from scratch with the Python standard library so
that each step can be explained in the report.
"""

from __future__ import annotations

import math
import random
from typing import Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# GCD and modular inverse
# ---------------------------------------------------------------------------


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm: gcd(a, b) = gcd(b, a mod b)."""
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    Iterative, so it does not hit Python's recursion limit on 4096-bit inputs.
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def modinv(a: int, n: int) -> int:
    """Multiplicative inverse of a modulo n (raises if gcd(a, n) != 1)."""
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {n} (gcd = {g})")
    return x % n


# ---------------------------------------------------------------------------
# Squares
# ---------------------------------------------------------------------------

# Quadratic residues mod 64, 63, 65 and 11: a cheap filter that rejects most
# non-squares before the (more expensive) integer square root is taken.
_QR64 = {(i * i) % 64 for i in range(64)}
_QR63 = {(i * i) % 63 for i in range(63)}
_QR65 = {(i * i) % 65 for i in range(65)}
_QR11 = {(i * i) % 11 for i in range(11)}


def is_square(n: int) -> Optional[int]:
    """Return sqrt(n) if n is a perfect square, otherwise None."""
    if n < 0:
        return None
    if (n & 63) not in _QR64:
        return None
    if n % 63 not in _QR63 or n % 65 not in _QR65 or n % 11 not in _QR11:
        return None
    r = math.isqrt(n)
    return r if r * r == n else None


def ceil_isqrt(n: int) -> int:
    """Smallest integer a with a*a >= n."""
    r = math.isqrt(n)
    return r if r * r == n else r + 1


# ---------------------------------------------------------------------------
# Primality and prime generation
# ---------------------------------------------------------------------------

_SMALL_PRIMES: List[int] = [p for p in range(3, 2000) if all(p % d for d in range(2, math.isqrt(p) + 1))]


def is_probable_prime(n: int, rounds: int = 40, rng: Optional[random.Random] = None) -> bool:
    """Miller-Rabin test. Error probability <= 4^-rounds for composite n."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    rng = rng or random.Random()
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int, rng: Optional[random.Random] = None) -> int:
    """Smallest probable prime strictly greater than n."""
    c = n + 1
    if c <= 2:
        return 2
    if c % 2 == 0:
        c += 1
    while not is_probable_prime(c, rng=rng):
        c += 2
    return c


def random_prime(bits: int, rng: random.Random) -> int:
    """Random prime with exactly `bits` bits (top two bits set, so that the
    product of two such primes has exactly 2*bits bits)."""
    if bits < 3:
        raise ValueError("bits must be >= 3")
    while True:
        c = rng.getrandbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(c, rng=rng):
            return c


# ---------------------------------------------------------------------------
# Continued fractions (used by Wiener's attack)
# ---------------------------------------------------------------------------


def continued_fraction(num: int, den: int) -> List[int]:
    """Partial quotients [a0; a1, a2, ...] of num/den.

    These are exactly the quotients produced by the Euclidean algorithm.
    """
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def convergents(cf: List[int]) -> Iterator[Tuple[int, int]]:
    """Yield the convergents h_i / k_i of a continued fraction.

    h_i = a_i * h_{i-1} + h_{i-2},  k_i = a_i * k_{i-1} + k_{i-2}
    """
    h_prev, h = 1, 0  # h_{-1}, h_{-2}
    k_prev, k = 0, 1
    for a in cf:
        h_prev, h = a * h_prev + h, h_prev
        k_prev, k = a * k_prev + k, k_prev
        yield h_prev, k_prev
