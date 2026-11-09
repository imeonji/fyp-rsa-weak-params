import random
import unittest

from rsaweak.attacks import factor_shared, fermat_factor, pairwise_gcd, batch_gcd, wiener_attack
from rsaweak.keygen import close_primes_key, shared_prime_keyset, small_d_key, standard_key
from rsaweak.rsa import private_key_from_factors, roundtrip_ok, verify_factors


class TestFermat(unittest.TestCase):
    def test_textbook_example(self):
        # 5959 = 59 * 101: a = 78 gives 78^2 - 5959 = 125 (not square), a = 80 gives 441 = 21^2
        r = fermat_factor(5959)
        self.assertEqual({r.p, r.q}, {59, 101})

    def test_breaks_close_primes_at_real_sizes(self):
        rng = random.Random(10)
        for bits in (512, 1024, 2048):
            key = close_primes_key(bits, gap_bits=bits // 4, rng=rng)
            r = fermat_factor(key.n)
            self.assertTrue(r.success)
            self.assertTrue(verify_factors(key.n, r.p, r.q))
            d = private_key_from_factors(key.public(), r.p, r.q)
            self.assertTrue(roundtrip_ok(key.public(), d))

    def test_gives_up_on_standard_key(self):
        key = standard_key(512, random.Random(11))
        r = fermat_factor(key.n, max_iterations=20_000)
        self.assertFalse(r.success)


class TestWiener(unittest.TestCase):
    def test_textbook_example(self):
        # Classic example: N = 90581, e = 17993 -> d = 5
        r = wiener_attack(17993, 90581)
        self.assertEqual(r.d, 5)
        self.assertEqual({r.p, r.q}, {239, 379})

    def test_breaks_small_d(self):
        rng = random.Random(20)
        for bits in (512, 1024, 2048):
            key = small_d_key(bits, d_bits=bits // 4 - 8, rng=rng)
            r = wiener_attack(key.e, key.n)
            self.assertTrue(r.success, bits)
            self.assertEqual(r.d, key.d)
            self.assertTrue(roundtrip_ok(key.public(), r.d))

    def test_fails_on_standard_key(self):
        key = standard_key(512, random.Random(21))
        self.assertFalse(wiener_attack(key.e, key.n).success)


class TestBatchGCD(unittest.TestCase):
    def test_finds_all_shared_primes(self):
        rng = random.Random(30)
        keys = shared_prime_keyset(count=40, bits=512, shared_pairs=3, rng=rng)
        moduli = [k.n for k in keys]
        found, _ = factor_shared(moduli)
        expected = {i for i, k in enumerate(keys) if k.label == "shared-prime"}
        self.assertEqual(set(found), expected)
        for i, (p, q) in found.items():
            self.assertTrue(verify_factors(moduli[i], p, q))

    def test_matches_pairwise(self):
        rng = random.Random(31)
        moduli = [k.n for k in shared_prime_keyset(count=25, bits=256, shared_pairs=4, rng=rng)]
        self.assertEqual(
            [g > 1 for g in batch_gcd(moduli)],
            [g > 1 for g in pairwise_gcd(moduli)],
        )


if __name__ == "__main__":
    unittest.main()
