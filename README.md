# rsa-weak-params

Final Year Project code: **Exploiting Weak Parameters in RSA: Implementation and
Empirical Evaluation of Classical Attacks at Real Key Sizes.**

Generates deliberately weak RSA keys and breaks them with classical
number-theoretic attacks. It also measures where each attack stops working at
real modulus sizes (1024 to 4096 bits).

Pure Python 3.9+, standard library only. Nothing to install.

## Attacks

| # | Weakness | Attack | Status | File |
|---|----------|--------|--------|------|
| 1 | p and q too close | Fermat factorisation | Done, benchmarked to 4096 bits | `rsaweak/attacks/fermat.py` |
| 2 | Private exponent d too small | Wiener (continued fractions) | Done, benchmarked to 2048 bits | `rsaweak/attacks/wiener.py` |
| 3 | Prime shared between moduli | Batch GCD (product/remainder trees) | Prototype, benchmarks planned Feb 2027 | `rsaweak/attacks/batch_gcd.py` |

## Layout

```
rsaweak/
  numtheory.py        gcd, extended Euclid, modular inverse, Miller-Rabin,
                      perfect-square test, continued fractions
  rsa.py              textbook RSA, key container, round-trip verification
  keygen.py           standard keys + three weak generators
  attacks/            fermat.py, wiener.py, batch_gcd.py
tests/                unit tests (textbook examples + 512-2048-bit keys)
benchmarks/           bench_fermat.py, bench_wiener.py -> results/*.csv
examples/demo.py      breaks one 2048-bit key with each attack
results/              benchmark CSVs
```

## Run it

```bash
python -m unittest discover -s tests -t .      # all tests, ~3 s
python -m examples.demo                        # end-to-end demo
python -m benchmarks.bench_fermat --bits 1024 2048 --trials 4
python -m benchmarks.bench_wiener --bits 1024 2048 --trials 20
```

All experiments use seeded random number generators, so the CSVs can be
reproduced exactly.

## Theory in one line each

- **Fermat:** N = a^2 - b^2 with a = (p+q)/2. Starting from a = ceil(sqrt N),
  it needs about (p - q)^2 / (8 sqrt N) steps. That is near zero when
  |p - q| < N^(1/4).
- **Wiener:** if d < N^(1/4)/3, then k/d is a convergent of the continued
  fraction of e/N. Trying each convergent recovers d in polynomial time.
- **Batch GCD:** gcd(N_i, product of all other N_j) exposes any shared prime.
  Product and remainder trees compute this for all i in quasi-linear time.

## Ethics

All keys are generated locally by this code. No real-world keys are collected
or attacked.

## References

- M. Wiener, "Cryptanalysis of short RSA secret exponents", IEEE Trans. Inf. Theory, 1990.
- N. Heninger, Z. Durumeric, E. Wustrow, J. A. Halderman, "Mining Your Ps and Qs", USENIX Security 2012.
- D. Boneh, "Twenty years of attacks on the RSA cryptosystem", Notices of the AMS, 1999.
- NIST FIPS 186-5, Digital Signature Standard, 2023 (Appendix A.1: RSA key-pair generation).
