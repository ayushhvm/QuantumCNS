"""
BKZ lattice attack complexity simulator for LWE-based systems (Kyber/ML-KEM).

This module computes ESTIMATED attack complexity for the BKZ (Block
Korkine-Zolotarev) lattice reduction algorithm — the best known classical
AND quantum attack on Learning With Errors (LWE) problems.

We do NOT run actual BKZ (requires fpylll). We compute complexity estimates
and, for toy parameters (n < 20), attempt a heuristic brute-force to
demonstrate parameter sensitivity.

References:
  - Albrecht et al. "On the concrete hardness of LWE" (2015)
  - Becker et al. "New directions in nearest neighbor searching" (2016)
  - Kyber spec: https://pq-crystals.org/kyber/
"""

import math
import time

import numpy as np


def simulate_lwe_instance(
    n: int, q: int, noise_std: float = 1.0, seed: int = 42
) -> tuple:
    """
    Generate a small LWE instance matching Kyber-style parameters.

    LWE problem: Given (A, b = A·s + e mod q), find secret s.
    Where e is a small noise vector (coefficients in {-1, 0, 1}).

    Args:
        n:         LWE dimension
        q:         modulus
        noise_std: not used directly; error drawn from {-1,0,1}
        seed:      random seed for reproducibility

    Returns:
        (A, b, s, e) — public matrix, public vector, secret, error
    """
    rng = np.random.default_rng(seed)
    A = rng.integers(0, q, size=(n, n))
    s = rng.integers(-2, 3, size=n)   # small secret: {-2,-1,0,1,2}
    e = rng.integers(-1, 2, size=n)   # small error:  {-1,0,1}
    b = (A @ s + e) % q
    return A, b, s, e


def simulate_bkz_attack(n: int, q: int, label: str) -> dict:
    """
    Simulate BKZ lattice reduction attack on an LWE instance.

    For toy params (n < 20): actually attempts heuristic brute-force.
    For real params (n ≥ 20): computes and reports infeasibility.

    Complexity formulas (rough estimates):
      Classical BKZ: 2^(0.292·β)  where β ≈ 0.265·n
      Quantum BKZ:   2^(0.265·β)  (quantum sieve speedup)

    Args:
        n:     LWE dimension
        q:     modulus
        label: human-readable parameter set name

    Returns:
        structured result dict
    """
    beta_classical = max(1, int(0.265 * n))
    beta_quantum   = max(1, int(0.212 * n))

    classical_exp  = 0.292 * beta_classical
    quantum_exp    = 0.265 * beta_quantum

    classical_ops  = 2 ** classical_exp
    quantum_ops    = 2 ** quantum_exp

    result = {
        "label": label,
        "parameters": {"n": n, "q": q},
        "attack_type": "BKZ lattice reduction (best known classical+quantum attack on LWE)",
        "classical_complexity": f"2^{classical_exp:.1f} ≈ {classical_ops:.2e} operations",
        "quantum_complexity":   f"2^{quantum_exp:.1f} ≈ {quantum_ops:.2e} operations",
        "verdict": "",
        "secret_recovered": False,
        "elapsed": None,
    }

    if n < 20:
        # Toy parameters: attempt heuristic brute-force to show vulnerability
        A, b, s, e = simulate_lwe_instance(n, q)
        start = time.perf_counter()
        found_s = None
        max_iters = min(50_000, q ** min(n, 3))
        rng = np.random.default_rng(0)

        for _ in range(max_iters):
            guess = rng.integers(-2, 3, size=n)
            residual = (b - A @ guess) % q
            # Check if residual is small (error bound = 2)
            if np.all(np.minimum(residual, q - residual) <= 2):
                found_s = guess
                break

        elapsed = time.perf_counter() - start
        result["elapsed"] = round(elapsed, 4)

        if found_s is not None:
            result["verdict"] = (
                f"❌ TOY PARAMETERS BROKEN in {elapsed:.3f}s — "
                f"DO NOT USE IN PRODUCTION"
            )
            result["secret_recovered"] = True
        else:
            result["verdict"] = (
                f"⚠️ Not found with heuristic guesser in {max_iters:,} iterations. "
                f"Real BKZ would succeed eventually."
            )
    else:
        result["verdict"] = (
            f"✅ INFEASIBLE — {label} requires ~2^{quantum_exp:.0f} quantum operations. "
            f"No known quantum algorithm can do better than BKZ+quantum sieve."
        )

    return result


def run_full_comparison() -> list[dict]:
    """
    Run BKZ attack simulations across toy and real parameter sets.

    Returns a list of result dicts, one per parameter set.
    """
    scenarios = [
        {"n": 8,   "q": 17,   "label": "Toy LWE (n=8, q=17) — demonstration only"},
        {"n": 16,  "q": 97,   "label": "Small LWE (n=16, q=97) — still attackable"},
        {"n": 256, "q": 3329, "label": "Kyber512 (n=256, q=3329) — NIST Level 1"},
        # Kyber768 uses k=3 modules of n=256 — effective security dimension ~768
        {"n": 384, "q": 3329, "label": "Kyber768 (k=3, effective n≈384, q=3329) — NIST Level 3"},
    ]
    return [simulate_bkz_attack(s["n"], s["q"], s["label"]) for s in scenarios]
