"""
================================================================================
  FastPrime-RSA   v2.3.1
  A lightweight RSA library "optimized for constrained devices"
================================================================================

  >>> THIS IS A DELIBERATELY FLAWED LIBRARY, CREATED FOR A SECURITY CODE-REVIEW
  >>> EXERCISE. Do not use it for anything real. It contains a hidden weakness
  >>> of the ROCA family (CVE-2017-15361). Your task is to find it.

  Scenario
  --------
  A (fictional) vendor, "FastPrime Systems", submits this library for
  certification. They claim it is ordinary, standards-conformant RSA, merely
  made faster on slow smartcard CPUs by a proprietary routine called "FastSeed".
  You are the evaluation lab. Decide whether the claims below actually hold.

  SECURITY TARGET  (the vendor's claims -- evaluate each one)
  -----------------------------------------------------------
    ST-1  Keys are standard RSA key pairs; primes are produced by probabilistic
          primality testing (Miller-Rabin).
    ST-2  Prime candidates are drawn uniformly at random -- every prime of the
          target size is (essentially) equally likely.
    ST-3  The proprietary "FastSeed" routine ONLY accelerates key generation.
          It does not change the statistical quality of the keys.
    ST-4  Given only the public modulus N, recovering the private factors is
          no easier than general-purpose integer factorization.

  HOW TO EVALUATE
  ---------------
  Run the companion script:   python3 evaluate_fastprime.py
  It walks you through functional testing, design review, and vulnerability
  analysis -- the same order a Common Criteria evaluation would follow.

  NOTE: key sizes here are intentionally tiny (~108-bit modulus) so the whole
  evaluation, including factorization, finishes in seconds in a classroom.
================================================================================
"""

import random
from math import gcd

PUBLIC_EXPONENT = 65537                      # standard RSA public exponent e


# ------------------------------------------------------------------------------
# Internal number-theory helpers
# ------------------------------------------------------------------------------
def _miller_rabin(n: int, rounds: int = 40) -> bool:
    """Probabilistic primality test (this part is correct and standard)."""
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _first_primes(count: int) -> list:
    out, n = [], 2
    while len(out) < count:
        if all(n % p for p in out):
            out.append(n)
        n += 1
    return out


def _multiplicative_order(g: int, M: int) -> int:
    """Smallest e with g**e == 1 (mod M)."""
    def factor(n):
        f, d = {}, 2
        while d * d <= n:
            while n % d == 0:
                f[d] = f.get(d, 0) + 1
                n //= d
            d += 1
        if n > 1:
            f[n] = f.get(n, 0) + 1
        return f
    lam = {}
    for p in factor(M):
        for q, e in factor(p - 1).items():
            lam[q] = max(lam.get(q, 0), e)
    order = 1
    for q, e in lam.items():
        order *= q ** e
    for q in lam:
        while order % q == 0 and pow(g, order // q, M) == 1:
            order //= q
    return order


# ==============================================================================
#  FastSeed acceleration table
# ------------------------------------------------------------------------------
#  Generating RSA primes on a weak smartcard CPU is slow: most random odd
#  integers are divisible by a small prime and waste an expensive Miller-Rabin
#  call. FastSeed avoids that. It builds candidates that are coprime to the
#  first 13 primes BY CONSTRUCTION, so almost every candidate survives the
#  cheap pre-checks and far fewer primality tests are needed.
#
#  A candidate prime is assembled as:
#
#        p  =  cofactor * FASTSEED_MODULUS  +  FASTSEED_BASE**seed mod FASTSEED_MODULUS
#
#  The second term is, by construction, a unit modulo FASTSEED_MODULUS -- i.e.
#  coprime to every one of those 13 small primes. That is the whole speed-up.
# ==============================================================================
FASTSEED_PRIMES = _first_primes(13)

FASTSEED_MODULUS = 1
for _p in FASTSEED_PRIMES:
    FASTSEED_MODULUS *= _p                   # = product of the first 13 primes

FASTSEED_BASE = 65537                        # generator used to build seed terms

# (computed once at import; used to bound the seed exponent below)
FASTSEED_ORDER = _multiplicative_order(FASTSEED_BASE, FASTSEED_MODULUS)


def _fast_prime() -> int:
    """
    Generate a prime using the FastSeed acceleration.

    Returns a prime of roughly FASTSEED_MODULUS.bit_length() + 5 bits.
    """
    while True:
        # Pick a seed term that is coprime to all 13 small primes.
        seed = random.randrange(FASTSEED_ORDER)
        seed_term = pow(FASTSEED_BASE, seed, FASTSEED_MODULUS)

        # A small cofactor lifts the candidate to the desired bit length.
        cofactor = random.randrange(16, 32)

        candidate = cofactor * FASTSEED_MODULUS + seed_term

        # The expensive test -- but reached far less often than in naive keygen.
        if _miller_rabin(candidate):
            return candidate


# ------------------------------------------------------------------------------
#  Public API
# ------------------------------------------------------------------------------
def generate_keypair() -> dict:
    """
    Generate a FastPrime-RSA key pair.

    Returns a dict with:
        public  = (N, e)
        private = (N, d)
        p, q    = the secret prime factors (exposed only for the lab)
    """
    while True:
        p = _fast_prime()
        q = _fast_prime()
        if p == q:
            continue
        N = p * q
        phi = (p - 1) * (q - 1)
        if gcd(PUBLIC_EXPONENT, phi) != 1:
            continue
        d = pow(PUBLIC_EXPONENT, -1, phi)
        return {"public": (N, PUBLIC_EXPONENT),
                "private": (N, d),
                "p": p, "q": q}


def encrypt(message: int, public_key: tuple) -> int:
    """Textbook RSA encryption:  c = m**e mod N."""
    N, e = public_key
    if not 0 <= message < N:
        raise ValueError("message must satisfy 0 <= m < N")
    return pow(message, e, N)


def decrypt(ciphertext: int, private_key: tuple) -> int:
    """Textbook RSA decryption:  m = c**d mod N."""
    N, d = private_key
    return pow(ciphertext, d, N)


# ------------------------------------------------------------------------------
#  Self-demo: a quick functional sanity check, exactly what a vendor would ship
#  to show "the product works". Run:  python3 fastprime_rsa.py
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    kp = generate_keypair()
    N, e = kp["public"]
    print(f"FastPrime-RSA v2.3.1  --  generated a {N.bit_length()}-bit key")
    print(f"  public  (N, e) = ({N}, {e})")
    for m in (2, 42, 123456789):
        c = encrypt(m, kp["public"])
        back = decrypt(c, kp["private"])
        print(f"  encrypt/decrypt {m:>10}  ->  {c}  ->  {back}   "
              f"{'OK' if back == m else 'FAIL'}")
    print("Functional self-test complete.")
