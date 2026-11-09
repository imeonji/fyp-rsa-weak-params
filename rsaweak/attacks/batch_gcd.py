"""Attack 3 (early prototype, scheduled for Feb 2027): batch GCD.

If two moduli share a prime, gcd(N1, N2) reveals it instantly. Checking all
pairs of m moduli takes m(m-1)/2 GCDs. Bernstein's product/remainder trees
(used by Heninger et al., "Mining Your Ps and Qs", 2012) find, for every
N_i, gcd(N_i, product of all the other N_j) in quasi-linear time:

    P = N_1 * N_2 * ... * N_m           (product tree)
    z_i = P mod N_i^2                   (remainder tree)
    g_i = gcd(N_i, z_i / N_i)

g_i > 1 means N_i shares a prime with some other modulus.
"""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

from ..numtheory import gcd


def product_tree(xs: List[int]) -> List[List[int]]:
    tree = [list(xs)]
    while len(tree[-1]) > 1:
        level = tree[-1]
        tree.append([level[i] * level[i + 1] if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)])
    return tree


def batch_gcd(moduli: List[int]) -> List[int]:
    """Return g_i = gcd(N_i, prod_{j != i} N_j) for every modulus."""
    tree = product_tree(moduli)
    rems = tree.pop()
    while tree:
        level = tree.pop()
        rems = [rems[i // 2] % (x * x) for i, x in enumerate(level)]
    return [gcd(r // n, n) for r, n in zip(rems, moduli)]


def pairwise_gcd(moduli: List[int]) -> List[int]:
    """Naive O(m^2) baseline, for comparison in the benchmarks."""
    out = [1] * len(moduli)
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g > 1:
                out[i] = out[i] if out[i] > 1 else g
                out[j] = out[j] if out[j] > 1 else g
    return out


def factor_shared(moduli: List[int]) -> Tuple[Dict[int, Tuple[int, int]], float]:
    """Factor every modulus that shares a prime with another one.

    Returns ({index: (p, q)}, seconds).
    """
    start = time.perf_counter()
    found = {}
    for i, (n, g) in enumerate(zip(moduli, batch_gcd(moduli))):
        if 1 < g < n:
            found[i] = (g, n // g)
        # g == n would mean both primes are shared; resolve with pairwise gcds.
        elif g == n:
            for j, m in enumerate(moduli):
                if j != i:
                    h = gcd(n, m)
                    if 1 < h < n:
                        found[i] = (h, n // h)
                        break
    return found, time.perf_counter() - start
