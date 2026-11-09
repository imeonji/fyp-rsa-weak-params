"""Benchmark Fermat factorisation against |p - q| at real modulus sizes.

For each modulus size and each gap size g (|p - q| ~ 2^g), generate keys with
close primes, run the attack, and record the measured iterations, the
predicted (p - q)^2 / (8 sqrt N) and the runtime.

Usage:
    python -m benchmarks.bench_fermat                 # default sweep
    python -m benchmarks.bench_fermat --bits 1024 --trials 3
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random

from rsaweak.attacks import fermat_factor, predicted_iterations
from rsaweak.keygen import close_primes_key, standard_key
from rsaweak.rsa import verify_factors

OFFSETS = [-100, -20, 0, 4, 8, 10, 12, 13]   # gap_bits - bits/4
MAX_ITER = 1 << 25


def run(bits_list, trials, seed, out):
    rng = random.Random(seed)
    rows = []
    for bits in bits_list:
        t = trials if bits <= 2048 else max(1, trials // 2)
        for off in OFFSETS:
            g = bits // 4 + off
            for trial in range(t):
                key = close_primes_key(bits, g, rng)
                r = fermat_factor(key.n, max_iterations=MAX_ITER)
                ok = r.success and verify_factors(key.n, r.p, r.q)
                diff = abs(key.p - key.q)
                row = dict(
                    bits=bits, gap_bits=g, offset=off, trial=trial,
                    log2_diff=round(math.log2(diff), 2),
                    predicted_iter=round(predicted_iterations(key.n, key.p, key.q), 1),
                    measured_iter=r.iterations, seconds=round(r.seconds, 6), success=ok,
                )
                rows.append(row)
                print(row, flush=True)
        # Control: a properly generated key, |p - q| ~ 2^(bits/2)
        key = standard_key(bits, rng)
        r = fermat_factor(key.n, max_iterations=MAX_ITER)
        row = dict(
            bits=bits, gap_bits="standard", offset="", trial=0,
            log2_diff=round(math.log2(abs(key.p - key.q)), 2),
            predicted_iter=f"2^{math.log2(predicted_iterations(key.n, key.p, key.q)):.0f}",
            measured_iter=r.iterations, seconds=round(r.seconds, 6), success=r.success,
        )
        rows.append(row)
        print(row, flush=True)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("wrote", out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, nargs="+", default=[1024, 2048, 4096])
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="results/fermat.csv")
    a = ap.parse_args()
    run(a.bits, a.trials, a.seed, a.out)
