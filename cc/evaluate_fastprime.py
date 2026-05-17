"""
================================================================================
  EVALUATION HARNESS  --  assessing FastPrime-RSA v2.3.1
================================================================================

  You are the evaluation lab. The vendor (FastPrime Systems) submitted
  `fastprime_rsa.py` together with a Security Target making four claims
  (ST-1 .. ST-4, see the top of that file).

  This harness walks the three stages a Common Criteria evaluation uses, in
  order. Run it and watch what each stage concludes:

      Stage A  -- Functional testing        (CC class ATE)
      Stage B  -- Design / source review    (CC class ADV)
      Stage C  -- Vulnerability analysis    (CC class AVA_VAN)

  The punch line: a product can sail through Stage A and still be broken in
  Stage C. That gap is the entire lesson of the ROCA story.

  Run:  python3 evaluate_fastprime.py     (keep fastprime_rsa.py in the same folder)
================================================================================
"""

from math import gcd, isqrt, log2

import fastprime_rsa as fp           # <-- the Target of Evaluation (TOE)


# ------------------------------------------------------------------------------
# Evaluator's own tools (the vendor does NOT provide these)
# ------------------------------------------------------------------------------
def discrete_log_bsgs(g: int, h: int, M: int, bound: int):
    """Baby-step/giant-step: find x in [0,bound) with g**x == h (mod M), else None."""
    m = isqrt(bound) + 1
    table, e = {}, 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % M
    factor = pow(g, -m, M)
    gamma = h % M
    for i in range(m + 1):
        if gamma in table:
            x = i * m + table[gamma]
            if x < bound:
                return x
        gamma = gamma * factor % M
    return None


def banner(text: str) -> None:
    print("\n" + "=" * 78 + f"\n  {text}\n" + "=" * 78)


# ==============================================================================
# STAGE A -- Functional testing (CC class ATE)
#   "Does the product do what an RSA library should do?"
# ==============================================================================
def stage_a_functional(trials: int = 25) -> bool:
    banner("STAGE A -- FUNCTIONAL TESTING  (CC class ATE)")
    kp = fp.generate_keypair()
    N, e = kp["public"]
    print(f"  Generated a {N.bit_length()}-bit key pair, e = {e}")

    import random
    ok = 0
    for _ in range(trials):
        m = random.randrange(N)
        if fp.decrypt(fp.encrypt(m, kp["public"]), kp["private"]) == m:
            ok += 1
    print(f"  encrypt -> decrypt round-trip: {ok}/{trials} messages recovered")

    passed = (ok == trials)
    print(f"  VERDICT (Stage A): {'PASS' if passed else 'FAIL'} "
          f"-- functionally it behaves exactly like RSA.")
    print("  Caution: passing functional tests says NOTHING about key strength.")
    return passed


# ==============================================================================
# STAGE B -- Design / source review (CC class ADV)
#   "Read the design. Does the implementation match the claims?"
# ==============================================================================
def stage_b_design_review() -> dict:
    banner("STAGE B -- DESIGN / SOURCE REVIEW  (CC class ADV)")
    M = fp.FASTSEED_MODULUS
    g = fp.FASTSEED_BASE
    order = fp.FASTSEED_ORDER

    print("  Inspecting the 'FastSeed' acceleration declared in fastprime_rsa.py:")
    print(f"    FASTSEED_BASE      g = {g}")
    print(f"    FASTSEED_MODULUS   M = {M}   ({M.bit_length()} bits)")
    print(f"    FASTSEED_ORDER       = {order}")

    # Each prime is  cofactor*M + g**seed mod M, with seed in [0, order)
    # and cofactor in [16, 32). Count how much entropy that really leaves.
    cofactor_bits = log2(32 - 16)
    roca_entropy = log2(order) + cofactor_bits
    sample_prime_bits = M.bit_length() + 5
    print()
    print(f"  The vendor claims primes are drawn 'uniformly at random' (ST-2).")
    print(f"  But a FastSeed prime is fully determined by (seed, cofactor):")
    print(f"    distinct seed values     : {order}  (~{log2(order):.1f} bits)")
    print(f"    distinct cofactor values : 16        (~{cofactor_bits:.1f} bits)")
    print(f"    => real entropy per prime : ~{roca_entropy:.1f} bits")
    print(f"    => a uniform {sample_prime_bits}-bit prime would have ~{sample_prime_bits} bits")

    red_flag = roca_entropy < sample_prime_bits / 2
    print()
    print(f"  RED FLAG: {'YES' if red_flag else 'no'} -- the implementation "
          f"contradicts ST-2 / ST-3.")
    print("  The comment says 'coprime to 13 small primes' (true) but omits that")
    print("  the construction also confines every prime to one tiny subgroup.")
    return {"M": M, "g": g, "order": order, "roca_entropy": roca_entropy}


# ==============================================================================
# STAGE C -- Vulnerability analysis (CC class AVA_VAN)
#   "Mount the actual attack a real adversary would use."
# ==============================================================================
def stage_c_vulnerability(design: dict) -> bool:
    banner("STAGE C -- VULNERABILITY ANALYSIS  (CC class AVA_VAN)")
    M, g, order = design["M"], design["g"], design["order"]

    # Take a fresh key -- the evaluator only gets the PUBLIC modulus.
    kp = fp.generate_keypair()
    N = kp["public"][0]
    print(f"  Target: public modulus N ({N.bit_length()} bits)")
    print(f"  (the private factors p, q are NOT given to the evaluator)\n")

    # --- C.1  Fingerprint: is N detectable as a FastSeed/ROCA key? -----------
    a = discrete_log_bsgs(g, N % M, M, order)
    if a is None:
        print("  Fingerprint test: NEGATIVE -- N is not a ROCA-style key.")
        return True
    print(f"  C.1  Fingerprint test: POSITIVE")
    print(f"       N mod M lies in the subgroup generated by {g}.")
    print(f"       leaked exponent sum a = seed_p + seed_q = {a}")

    # --- C.2  Factor N by enumerating the low-entropy secret ----------------
    print(f"  C.2  Factoring N by searching {order} seeds x small cofactors ...")
    found = None
    for seed in range(order):
        seed_term = pow(g, seed, M)
        for cofactor in range(0, 40):
            cand = cofactor * M + seed_term
            if cand > 1 and N % cand == 0:
                found = (cand, N // cand)
                break
        if found:
            break

    if not found:
        print("       factorization failed (unexpected) -- widen the cofactor range.")
        return False
    p, q = found
    print(f"       FACTORED:  p = {p}")
    print(f"                  q = {q}")
    print(f"       check p*q == N : {p * q == N}")

    # --- C.3  Recover the private key ---------------------------------------
    phi = (p - 1) * (q - 1)
    d = pow(fp.PUBLIC_EXPONENT, -1, phi)
    secret = 0xC0FFEE
    forged = fp.decrypt(fp.encrypt(secret, kp["public"]), (N, d))
    print(f"  C.3  Reconstructed private exponent d from the factors.")
    print(f"       decrypting with the recovered d returns the plaintext: "
          f"{forged == secret}")
    print(f"\n  VERDICT (Stage C): FAIL -- the private key is recoverable from")
    print(f"  the public key alone. ST-4 is violated.")
    return False


# ==============================================================================
# Final evaluation report
# ==============================================================================
def main() -> None:
    a_pass = stage_a_functional()
    design = stage_b_design_review()
    c_pass = stage_c_vulnerability(design)

    banner("EVALUATION REPORT -- mapping results to the Security Target")
    rows = [
        ("ST-1  standard RSA, Miller-Rabin primes",
         "MET",     "the library genuinely implements RSA correctly"),
        ("ST-2  primes drawn uniformly at random",
         "NOT MET", "primes are confined to a tiny subgroup (Stage B)"),
        ("ST-3  FastSeed only accelerates, no quality loss",
         "NOT MET", "FastSeed destroys ~2/3 of the key entropy (Stage B)"),
        ("ST-4  N reveals nothing faster than factoring",
         "NOT MET", "N is fingerprinted and factored in seconds (Stage C)"),
    ]
    for claim, status, why in rows:
        print(f"  [{status:^7}]  {claim}")
        print(f"             reason: {why}")
    print()
    print("  OVERALL: the product PASSES functional testing but FAILS")
    print("  vulnerability analysis. Certification must be DENIED.")
    print()
    print("  Lesson: a Security Target is a set of CLAIMS. Evaluation is only")
    print("  as strong as the analysis applied to them -- Stage A alone would")
    print("  have certified a fundamentally broken product. This is exactly")
    print("  how ROCA-vulnerable chips obtained Common Criteria certificates.")


# ==============================================================================
# >>> STUDENT EXERCISES <<<
# ------------------------------------------------------------------------------
# EXERCISE 1 (find it yourself)
#   BEFORE running this harness, open fastprime_rsa.py and review `_fast_prime`
#   line by line as if you were the evaluator. Write down the single line that
#   collapses the key entropy, and explain in two sentences why the surrounding
#   comment is technically true yet misleading.
#
# EXERCISE 2 (black-box detection)
#   stage_c uses M and g read from the vendor's source (a white-box evaluation).
#   A real attacker may not have the source. Modify the fingerprint test so it
#   works WITHOUT importing fastprime_rsa -- testing N against several small
#   candidate moduli. (Hint: this is what the real `roca-detect` tool does.)
#
# EXERCISE 3 (cost estimate)
#   Stage C factors a ~108-bit key instantly. Using FASTSEED_ORDER, estimate the
#   work for the real Infineon parameters (subgroup order ~2^62). Why is brute
#   force hopeless there, and what does the real attack use instead?
#
# EXERCISE 4 (fix the product)
#   Patch `_fast_prime` so the library still generates primes efficiently but
#   Stage B no longer raises a red flag and Stage C's fingerprint goes NEGATIVE.
#   What is the minimal change? What does that reveal about the root cause?
#
# REAL-WORLD ARTIFACTS (for the curious)
#   The original detection tool and parameters are public: the CRoCS "roca"
#   tool (a.k.a. roca-detect) and the paper Nemec et al., "The Return of
#   Coppersmith's Attack", ACM CCS 2017.
# ==============================================================================

if __name__ == "__main__":
    main()
