import random
import unittest
from fractions import Fraction

from rsaweak.numtheory import (
    continued_fraction, convergents, egcd, gcd, is_probable_prime, is_square,
    modinv, next_prime, random_prime,
)


class TestNumberTheory(unittest.TestCase):
    def test_gcd_and_egcd(self):
        rng = random.Random(1)
        for _ in range(200):
            a, b = rng.getrandbits(256), rng.getrandbits(256) + 1
            g, x, y = egcd(a, b)
            self.assertEqual(g, gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_modinv(self):
        self.assertEqual(modinv(3, 11), 4)
        self.assertEqual((17 * modinv(17, 3120)) % 3120, 1)
        with self.assertRaises(ValueError):
            modinv(6, 9)

    def test_is_square(self):
        rng = random.Random(2)
        for _ in range(200):
            r = rng.getrandbits(600)
            self.assertEqual(is_square(r * r), r)
            self.assertIsNone(is_square(r * r + 1) if r else None)
        self.assertIsNone(is_square(-4))

    def test_primality(self):
        primes = [p for p in range(2, 3000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]
        for n in range(3000):
            self.assertEqual(is_probable_prime(n), n in primes, n)
        # Carmichael numbers fool Fermat's test but not Miller-Rabin
        for c in (561, 41041, 825265, 321197185, 5394826801):
            self.assertFalse(is_probable_prime(c))
        self.assertTrue(is_probable_prime(2 ** 127 - 1))
        self.assertEqual(next_prime(100), 101)

    def test_random_prime_size(self):
        rng = random.Random(3)
        for bits in (64, 256, 512):
            p = random_prime(bits, rng)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_probable_prime(p))

    def test_continued_fraction(self):
        # 649/200 = [3; 4, 12, 4]
        self.assertEqual(continued_fraction(649, 200), [3, 4, 12, 4])
        convs = list(convergents([3, 4, 12, 4]))
        self.assertEqual(convs[-1], (649, 200))
        self.assertEqual(convs[0], (3, 1))
        self.assertEqual(Fraction(*convs[1]), Fraction(13, 4))


if __name__ == "__main__":
    unittest.main()
