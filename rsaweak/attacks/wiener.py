"""Attack 2: Wiener's small private exponent attack (Wiener, 1990).

Idea
----
From ed = 1 + k*phi(N) we get

    e/phi(N) - k/d = 1 / (d * phi(N)).

Because phi(N) is close to N, k/d is a very good approximation of e/N.
Legendre's theorem says that if |x - k/d| < 1/(2 d^2), then k/d is one of
the convergents of the continued fraction of x. Wiener showed this holds for
x = e/N whenever q < p < 2q and d < N^(1/4) / 3.

So: expand e/N as a continued fraction, and for each convergent k/d
  1. skip it unless k divides ed - 1;
  2. compute the candidate phi = (ed - 1) / k;
  3. p + q = N - phi + 1, so p and q are the roots of x^2 - (N - phi + 1)x + N;
  4. if the discriminant is a perfect square, the roots are the factors.

The continued fraction of e/N has O(log N) terms, so the attack is
polynomial time: it breaks a vulnerable 2048-bit key in milliseconds.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Optional

from ..numtheory import continued_fraction, convergents, is_square


@dataclass
class WienerResult:
    d: Optional[int]
    p: Optional[int]
    q: Optional[int]
    convergents_tried: int
    seconds: float

    @property
    def success(self) -> bool:
        return self.d is not None


def wiener_bound(n: int) -> float:
    """Wiener's bound N^(1/4) / 3, as a float of bits (log2)."""
    return math.log2(math.isqrt(math.isqrt(n))) - math.log2(3)


def wiener_attack(e: int, n: int) -> WienerResult:
    start = time.perf_counter()
    tried = 0
    for k, d in convergents(continued_fraction(e, n)):
        tried += 1
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1           # p + q
        disc = s * s - 4 * n      # (p - q)^2
        t = is_square(disc)
        if t is None or (s + t) % 2:
            continue
        p, q = (s + t) // 2, (s - t) // 2
        if q > 1 and p * q == n:
            return WienerResult(d, p, q, tried, time.perf_counter() - start)
    return WienerResult(None, None, None, tried, time.perf_counter() - start)
