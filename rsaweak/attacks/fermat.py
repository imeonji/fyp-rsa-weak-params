"""Attack 1: Fermat's factorisation method.

Idea
----
If N = pq with p > q, write

    a = (p + q) / 2,   b = (p - q) / 2,   so   N = a^2 - b^2 = (a - b)(a + b).

Start at a = ceil(sqrt(N)) and step a upward until a^2 - N is a perfect
square b^2. Then p = a + b, q = a - b.

Cost
----
The number of steps is a_final - ceil(sqrt(N)) where a_final = (p + q)/2.
Since (p + q)/2 - sqrt(pq) = (sqrt(p) - sqrt(q))^2 / 2 ~ (p - q)^2 / (8 sqrt(N)),

    iterations ~ (p - q)^2 / (8 * sqrt(N)).

So for a 2048-bit N (sqrt(N) ~ 2^1024), the attack finishes in about one
step when |p - q| < 2^513, and in about 2^20 steps when |p - q| ~ 2^523.
For properly generated primes (|p - q| ~ 2^1023) it would need ~2^1019 steps.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Optional

from ..numtheory import ceil_isqrt, is_square


@dataclass
class FermatResult:
    p: Optional[int]
    q: Optional[int]
    iterations: int
    seconds: float

    @property
    def success(self) -> bool:
        return self.p is not None


def predicted_iterations(n: int, p: int, q: int):
    """Theoretical step count (p - q)^2 / (8 sqrt(N)).

    Returned as a float when it fits, otherwise as an exact int (for
    properly generated 4096-bit keys it is about 2^2040, past float range).
    """
    num, den = (p - q) ** 2, 8 * math.isqrt(n)
    whole, rem = divmod(num, den)
    return whole + rem / den if whole < (1 << 1000) else whole


def fermat_factor(n: int, max_iterations: int = 10_000_000) -> FermatResult:
    """Factor n with Fermat's method, giving up after max_iterations steps.

    b2 = a^2 - N is updated incrementally: going from a to a+1 adds 2a + 1,
    so each step costs one addition plus a perfect-square check.
    """
    start = time.perf_counter()
    if n % 2 == 0:
        return FermatResult(2, n // 2, 0, time.perf_counter() - start)
    a = ceil_isqrt(n)
    b2 = a * a - n
    for i in range(max_iterations + 1):
        b = is_square(b2)
        if b is not None:
            p, q = a + b, a - b
            if q > 1:
                return FermatResult(p, q, i, time.perf_counter() - start)
        b2 += 2 * a + 1
        a += 1
    return FermatResult(None, None, max_iterations, time.perf_counter() - start)
