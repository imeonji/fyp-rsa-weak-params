"""End-to-end demo: generate one weak 2048-bit key of each kind and break it.

    python -m examples.demo
"""

import random
import time

from rsaweak.attacks import factor_shared, fermat_factor, wiener_attack
from rsaweak.keygen import close_primes_key, shared_prime_keyset, small_d_key
from rsaweak.rsa import encrypt, decrypt, private_key_from_factors

BITS = 2048
rng = random.Random(42)
secret = int.from_bytes(b"FYP demo message", "big")


def show(title):
    print("\n" + title)
    print("-" * len(title))


show(f"Attack 1: Fermat factorisation, {BITS}-bit N, |p - q| ~ 2^520")
t = time.perf_counter()
key = close_primes_key(BITS, gap_bits=520, rng=rng)
print(f"key generated in {time.perf_counter() - t:.1f}s; N has {key.n.bit_length()} bits")
c = encrypt(secret, key.public())
r = fermat_factor(key.n)
d = private_key_from_factors(key.public(), r.p, r.q)
print(f"factored in {r.iterations} iterations, {r.seconds * 1000:.2f} ms")
print("decrypted:", decrypt(c, key.n, d).to_bytes(16, "big"))

show(f"Attack 2: Wiener, {BITS}-bit N, d of {BITS // 4 - 8} bits")
key = small_d_key(BITS, d_bits=BITS // 4 - 8, rng=rng)
c = encrypt(secret, key.public())
r = wiener_attack(key.e, key.n)
print(f"recovered d after {r.convergents_tried} convergents, {r.seconds * 1000:.2f} ms")
print("decrypted:", decrypt(c, key.n, r.d).to_bytes(16, "big"))

show("Attack 3 (prototype): batch GCD over 30 keys of 512 bits, 2 pairs share a prime")
keys = shared_prime_keyset(30, 512, shared_pairs=2, rng=rng)
found, secs = factor_shared([k.n for k in keys])
print(f"factored {len(found)} of {len(keys)} moduli in {secs * 1000:.2f} ms: indices {sorted(found)}")
