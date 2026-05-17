"""
Shor's period-finding classical simulation.

This module classically brute-forces the period-finding step that a real quantum
computer would solve using the Quantum Fourier Transform (QFT).

Amendment 6: N is capped at 9999 (enforced in Flask route, validated here too).
"""

import math
import time


def simulate_shors_period_finding(N: int, a: int = 2) -> dict:
    """
    Classically simulate the period-finding subroutine of Shor's algorithm.

    In a real quantum computer, Quantum Phase Estimation + QFT finds the period
    in O(log³N) time. This brute-forces it classically to demonstrate the LOGIC.

    Args:
        N: number to factor (simulates RSA/ECDH modulus). Amendment 6: N ≤ 9999.
        a: base for modular exponentiation (must be coprime to N)

    Returns:
        dict with period, factors, steps, time_taken, quantum_note
    """
    # Amendment 6: enforce cap
    if N > 9999:
        return {
            "N": N,
            "error": "N exceeds cap of 9999. Use /api/simulate/quantum_shors for larger N.",
            "success": False,
        }
    if N < 4:
        return {"N": N, "error": "N must be ≥ 4", "success": False}

    report = {
        "N": N,
        "a": a,
        "steps": [],
        "success": False,
        "factors": None,
        "period": None,
        "time_taken": None,
        "quantum_note": "",
    }

    start = time.perf_counter()

    g = math.gcd(a, N)
    if g != 1:
        # Lucky — a shares a factor with N already
        report["steps"].append(f"gcd({a}, {N}) = {g} ≠ 1 — trivial factor found!")
        if g != N:
            report["success"] = True
            report["factors"] = (g, N // g)
            report["steps"].append(f"✅ Trivial factorization: {N} = {g} × {N // g}")
        report["time_taken"] = time.perf_counter() - start
        return report

    report["steps"].append(f"Step 1: Pick a={a}, verify gcd({a},{N})=1 ✓")
    report["steps"].append(
        f"Step 2: [QUANTUM] QFT finds period of f(x) = {a}^x mod {N}"
    )
    report["steps"].append(
        f"Step 2: [CLASSICAL SIM] Brute-forcing period (exponentially slower)..."
    )

    # Find smallest r > 0 such that a^r ≡ 1 (mod N), cap at N*N
    r = None
    search_cap = min(N * N, 10_000_000)
    for x in range(1, search_cap + 1):
        if pow(a, x, N) == 1:
            r = x
            break

    if r is None:
        report["steps"].append("Period not found in search range")
        report["time_taken"] = time.perf_counter() - start
        return report

    report["period"] = r
    report["steps"].append(f"Step 3: Period found: r = {r}")

    if r % 2 != 0:
        report["steps"].append(f"r={r} is odd — retry with different a")
        report["time_taken"] = time.perf_counter() - start
        return report

    half = pow(a, r // 2, N)
    if half == N - 1:
        report["steps"].append(f"a^(r/2) ≡ -1 (mod N) — retry with different a")
        report["time_taken"] = time.perf_counter() - start
        return report

    factor1 = math.gcd(half - 1, N)
    factor2 = math.gcd(half + 1, N)

    report["steps"].append(f"Step 4: Compute gcd({a}^(r/2) ± 1, {N})")
    report["steps"].append(f"Step 5: Candidates: {factor1} and {factor2}")

    if factor1 * factor2 == N and factor1 > 1 and factor2 > 1:
        report["success"] = True
        report["factors"] = (factor1, factor2)
        report["steps"].append(f"✅ FACTORED: {N} = {factor1} × {factor2}")
        report["steps"].append("🔑 ECDH private key can be derived from public key!")
    else:
        report["steps"].append("⚠️ Factor extraction failed — try different a")

    report["time_taken"] = time.perf_counter() - start
    report["quantum_note"] = (
        f"A quantum computer solves this in O(log³({N})) ≈ "
        f"{int(math.log2(N) ** 3)} quantum operations using QFT. "
        f"Classical simulation took {report['time_taken']:.4f}s brute-forcing."
    )
    return report


def extrapolate_to_p256() -> dict:
    """
    Extrapolate Shor's attack to P-256 ECDH at cryptographic scale.
    Complexity estimates only — no computation attempted.
    Sources: Roetteler et al. 2017 (arXiv:1706.06752).
    """
    p256_bits = 256
    return {
        "target": "ECDHE P-256 (classical key exchange used in PQChat)",
        "classical_security_bits": 128,
        "shor_quantum_ops": (
            f"O(log³(2^{p256_bits})) = O({p256_bits}³) "
            f"= O({p256_bits**3:,}) quantum gate operations"
        ),
        "logical_qubits_needed": "~2,330 (Roetteler et al. 2017, arXiv:1706.06752)",
        "physical_qubits_needed": "~4,000,000+ (surface code overhead ~1000x)",
        "current_best_hardware": "IBM Heron r2: 156 qubits (noisy, not error-corrected)",
        "gap_to_break": "~25,000x more physical qubits needed than currently available",
        "verdict": "VULNERABLE IN PRINCIPLE — not breakable today",
        "protection_in_pqchat": "Kyber768 hybrid: session key safe even if ECDHE is broken",
    }
