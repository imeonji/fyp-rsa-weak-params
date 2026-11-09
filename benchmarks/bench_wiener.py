"""Benchmark Wiener's attack: success rate as d grows past N^(1/4) / 3.

For each modulus size and each private-exponent size d_bits, generate
`trials` keys with a random d of exactly d_bits bits and record whether the
attack recovered d, how many convergents it tried, and the runtime.

Usage:
    python -m benchmarks.bench_wiener
    python -m benchmarks.bench_wiener --bits 1024 --trials 50
"""

from __future__ import annotations

import argparse
import csv
import os
import random

from rsaweak.attacks import wiener_attack, wiener_bound
from rsaweak.keygen import small_d_key
from rsaweak.rsa import roundtrip_ok

OFFSETS = [-32, -16, -8, -4, -3, -2, -1, 0, 1, 2, 4, 8]   # d_bits - bits/4


def run(bits_list, trials, seed, out):
    rng = random.Random(seed)
    rows = []
    for bits in bits_list:
        for off in OFFSETS:
            d_bits = bits // 4 + off
            wins, secs, tried = 0, [], []
            bound = None
            for _ in range(trials):
                key = small_d_key(bits, d_bits, rng)
                bound = wiener_bound(key.n)
                r = wiener_attack(key.e, key.n)
                ok = r.success and r.d == key.d and roundtrip_ok(key.public(), r.d)
                wins += ok
                secs.append(r.seconds)
                tried.append(r.convergents_tried)
            row = dict(
                bits=bits, d_bits=d_bits, offset=off,
                bound_bits=round(bound, 2), trials=trials, successes=wins,
                success_rate=round(wins / trials, 3),
                mean_ms=round(1000 * sum(secs) / len(secs), 3),
                mean_convergents=round(sum(tried) / len(tried), 1),
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
    ap.add_argument("--bits", type=int, nargs="+", default=[1024, 2048])
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="results/wiener.csv")
    a = ap.parse_args()
    run(a.bits, a.trials, a.seed, a.out)
