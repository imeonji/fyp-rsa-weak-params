# Lab notes

Dated record of what was built, decisions taken, and raw results.
Newest entry first. Source data for every number is in `results/`.

---

## 2026-11-09: Attacks 1 and 2 implemented and benchmarked; batch GCD prototyped

### Built

| Component | File | Notes |
|---|---|---|
| Number theory helpers | `rsaweak/numtheory.py` | gcd, iterative extended Euclid, modinv, Miller-Rabin (40 rounds), perfect-square test with QR filters mod 64/63/65/11, continued fractions, convergents |
| Textbook RSA | `rsaweak/rsa.py` | key container, encrypt/decrypt, `verify_factors`, `roundtrip_ok` |
| Key generators | `rsaweak/keygen.py` | `standard_key`, `close_primes_key(bits, gap_bits)`, `small_d_key(bits, d_bits)`, `shared_prime_keyset` |
| Fermat | `rsaweak/attacks/fermat.py` | incremental b^2 update; iteration cap |
| Wiener | `rsaweak/attacks/wiener.py` | convergents of e/N; root recovery from p+q |
| Batch GCD | `rsaweak/attacks/batch_gcd.py` | product/remainder tree + pairwise baseline; prototype only |
| Tests | `tests/` | 14 unit tests, all pass (about 2.3 s) |

### Decisions

- Pure Python standard library only, so results are reproducible without setup.
- Textbook (unpadded) RSA: the project is about parameters, not padding.
- `close_primes_key`: q = nextprime(p + delta), delta has exactly `gap_bits` bits.
- `small_d_key`: d chosen first with exact bit length, e = d^-1 mod phi; primes satisfy q < p < 2q.
- All runs seeded (2026 for 1024/2048-bit runs, 4096 for the 4096-bit Fermat run).
- Success is accepted only if p*q = N **and** a test ciphertext decrypts with the recovered key.

### Results: Fermat (`results/fermat.csv`, `results/fermat_4096.csv`)

- 72 weak keys (32 at 1024, 32 at 2048, 8 at 4096 bits): all factored.
- Measured iterations vs predicted (p-q)^2 / (8 sqrt N): max difference 1 iteration.
- 27 keys with |p-q| <= 2^(n/4) factored at iteration 0.
- Throughput about 2.1 million iterations/s.
- 2048-bit: |p-q| up to about 2^525 factored in at most 4.8 s.
- Control keys (|p-q| about 2^(n/2)): not factored within 2^25 iterations (12 s, 16 s, 20 s at 1024, 2048, 4096 bits).

| bits | gap_bits | runs | iterations (min to max) | seconds (max) |
|---|---|---|---|---|
| 1024 | 260 | 4 | 9 to 23 | 0.00004 |
| 1024 | 264 | 4 | 2,434 to 8,060 | 0.002 |
| 1024 | 266 | 4 | 50,930 to 146,080 | 0.071 |
| 1024 | 268 | 4 | 613,558 to 2,472,284 | 0.771 |
| 1024 | 269 | 4 | 4,042,760 to 6,645,560 | 2.873 |
| 2048 | 516 | 4 | 13 to 26 | 0.00005 |
| 2048 | 520 | 4 | 6,884 to 7,394 | 0.007 |
| 2048 | 522 | 4 | 50,755 to 126,273 | 0.087 |
| 2048 | 524 | 4 | 856,279 to 1,264,591 | 0.662 |
| 2048 | 525 | 4 | 2,495,631 to 8,580,372 | 4.781 |
| 4096 | 1028 | 1 | 38 | 0.0001 |
| 4096 | 1032 | 1 | 3,728 | 0.002 |
| 4096 | 1034 | 1 | 157,844 | 0.087 |
| 4096 | 1036 | 1 | 1,488,603 | 0.730 |
| 4096 | 1037 | 1 | 8,034,475 | 3.729 |

### Results: Wiener (`results/wiener.csv`, 20 keys per row)

Offset = bit length of d minus n/4. Wiener bound N^(1/4)/3 sits at about offset -1.67.

| offset | 1024-bit success | 2048-bit success |
|---|---|---|
| -32 to -2 | 100% | 100% |
| -1 | 100% | 100% |
| 0 | 35% | 60% |
| +1 | 20% | 15% |
| +2 | 10% | 5% |
| +4 | 0% | 0% |
| +8 | 0% | 0% |

- Mean time: 0.4 to 2.5 ms on success; about 10 ms on failure (2048-bit).
- Convergents tried: about 150 (1024) / 300 (2048) on success; about 600 / 1,200 on failure.

### Batch GCD

- Correct on 40 keys of 512 bits with 3 shared pairs (all 6 found, no false positives).
- Matches pairwise baseline on 25 keys of 256 bits.
- Not benchmarked yet (planned December).

### Fixes

- `predicted_iterations` overflowed float for 4096-bit control keys; now returns an exact int when the value exceeds 2^1000.

### Open items

- Scale batch GCD benchmark (thousands of keys).
- Choose extension: Boneh-Durfee (code-heavy) vs Pollard p-1 (light). Ask supervisor.
