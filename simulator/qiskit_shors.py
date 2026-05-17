"""
Shor's Algorithm quantum circuit simulation using Qiskit 2.x + AerSimulator.

Reference: Qiskit Textbook "Shor's Algorithm" chapter.
This implements the standard quantum phase estimation + QFT approach.
Only valid for small N (≤ 35) due to exponential RAM requirements.

Qiskit version: 2.4.0
qiskit-aer version: 0.17.2
"""

import math
import time
import warnings
from fractions import Fraction

warnings.filterwarnings("ignore", category=DeprecationWarning)

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


# ---------------------------------------------------------------------------
# Modular exponentiation gate (unitary for f(x) = a^x mod N)
# ---------------------------------------------------------------------------

def _c_amod15(a: int, power: int) -> QuantumCircuit:
    """
    Controlled unitary implementing a^(2^power) mod 15.
    Only works for N=15 and a in {2, 4, 7, 8, 11, 13}.
    Used for the N=15 demo circuit.
    Source: Qiskit textbook, Chapter 10.
    """
    U = QuantumCircuit(4)
    for _ in range(power):
        if a in {2, 13}:
            U.swap(0, 1); U.swap(1, 2); U.swap(2, 3)
        if a in {7, 8}:
            U.swap(2, 3); U.swap(1, 2); U.swap(0, 1)
        if a in {4, 11}:
            U.swap(1, 3); U.swap(0, 2)
        if a in {3, 12}:
            U.swap(1, 3); U.swap(0, 2); U.swap(0, 1)
    U = U.to_gate()
    U.name = f"{a}^{power} mod 15"
    c_U = U.control()
    return c_U


def _qft_dagger(n: int) -> QuantumCircuit:
    """
    Inverse QFT on n qubits.
    Source: Qiskit textbook, Chapter 9.
    """
    qc = QuantumCircuit(n)
    for qubit in range(n // 2):
        qc.swap(qubit, n - qubit - 1)
    for j in range(n):
        for m in range(j):
            qc.cp(-math.pi / float(2 ** (j - m)), m, j)
        qc.h(j)
    qc.name = "QFT†"
    return qc


def _build_shors_circuit_n15(n_count: int, a: int) -> QuantumCircuit:
    """
    Build Shor's circuit for N=15 with QPE resolution n_count.
    Source: Qiskit textbook, Chapter 10.
    """
    qc = QuantumCircuit(n_count + 4, n_count)

    # Hadamard on counting qubits
    for q in range(n_count):
        qc.h(q)

    # Target register starts in |1>
    qc.x(3 + n_count)

    # Controlled-U^(2^j) gates
    for q in range(n_count):
        qc.append(_c_amod15(a, 2**q), [q] + [i + n_count for i in range(4)])

    # Inverse QFT on counting register
    qc.append(_qft_dagger(n_count), range(n_count))

    # Measure counting qubits
    qc.measure(range(n_count), range(n_count))
    return qc


def _extract_period_from_counts(counts: dict, n_count: int, N: int) -> int | None:
    """
    Use continued fractions to extract period r from measurement results.
    Takes the most frequent measurement as the phase estimate.
    """
    # Sort by count descending, try top 5
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)

    for bitstring, _ in sorted_counts[:5]:
        # Reverse bitstring (Qiskit bit-ordering)
        integer = int(bitstring[::-1], 2)
        phase = integer / (2 ** n_count)

        if phase == 0:
            continue

        # Continued fraction approximation
        frac = Fraction(phase).limit_denominator(N)
        candidate_r = frac.denominator

        if candidate_r > 0 and pow(2, candidate_r, N) == 1:
            return candidate_r

    return None


def run_shors_simulation(N: int, a: int = None) -> dict:
    """
    Run Shor's algorithm for factoring N using Qiskit AerSimulator.

    Only reliable for N=15. For other small N ≤ 35, attempts but may fail.
    The quantum circuit for N=15 is exact (textbook implementation).
    For other N, falls back to phase estimation approximation.

    Args:
        N: integer to factor (must be ≤ 35, enforced by Flask route)
        a: base (if None, tried in order [2, 3, 4, 5, 7])

    Returns:
        Structured result dict (see module docstring).
    """
    if N > 35:
        return {
            "N": N,
            "error": "N too large for Qiskit simulation (max 35)",
            "success": False,
        }

    n_count = 8  # counting qubits — resolution for phase estimation
    candidates_a = [a] if a is not None else [2, 3, 4, 5, 7]

    steps = []
    steps.append(f"Target: Factor N={N} using Shor's Algorithm")
    steps.append(f"Backend: AerSimulator (classical quantum circuit simulation)")
    steps.append(f"Shots: 1024 (statistical sampling of measurement outcomes)")

    sim = AerSimulator()
    start = time.perf_counter()

    # Only the N=15 textbook circuit is guaranteed correct
    if N != 15:
        steps.append(
            f"⚠️ Exact modular exponentiation circuit only implemented for N=15. "
            f"Falling back to classical period-finding for N={N}."
        )
        # Use classical period finding and wrap in quantum-style report
        from simulator.shors_simulation import simulate_shors_period_finding
        classical = simulate_shors_period_finding(N, candidates_a[0])
        classical["mode"] = "classical_fallback_for_non_15"
        classical["quantum_note"] = (
            f"Qiskit circuit only implemented for N=15 (textbook). "
            f"For N={N}, classical period-finding used. "
            f"A real quantum computer would use a generic modular exponentiation circuit."
        )
        classical["qubit_count"] = n_count + 4
        classical["circuit_depth"] = "N/A (not built for this N)"
        classical["shots"] = 1024
        classical["runtime_seconds"] = round(time.perf_counter() - start, 4)
        return classical

    # N=15: run full Qiskit textbook circuit
    best_result = None
    circuit_diagram = ""

    for a_try in candidates_a:
        g = math.gcd(a_try, N)
        if g != 1:
            steps.append(f"a={a_try}: gcd({a_try},{N})={g} — trivial factor found!")
            runtime = time.perf_counter() - start
            return {
                "N": N, "a": a_try, "success": True,
                "factors": [g, N // g],
                "period": None,
                "qubit_count": 0, "circuit_depth": 0, "shots": 0,
                "top_measurements": {},
                "circuit_diagram": "Trivial factorization — no circuit needed",
                "steps": steps,
                "runtime_seconds": round(runtime, 4),
                "quantum_note": f"gcd({a_try},{N})={g} found classically before running circuit.",
            }

        steps.append(f"Trying a={a_try}...")
        steps.append(f"Step 1: Building QPE circuit with {n_count} counting qubits")

        qc = _build_shors_circuit_n15(n_count, a_try)
        circuit_diagram = qc.draw(output="text").single_string()

        steps.append(f"Step 2: Circuit has {qc.num_qubits} qubits, depth {qc.depth()}")
        steps.append("Step 3: [QUANTUM] QFT finds period by measuring phase of eigenvalue")
        steps.append("Step 3: [AerSim]  Simulating 1024 shots...")

        transpiled = transpile(qc, sim)
        job = sim.run(transpiled, shots=1024)
        result = job.result()
        counts = result.get_counts()

        # Top 5 measurements
        top5 = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5])
        steps.append(f"Step 4: Top measurement: {list(top5.keys())[0]}")

        r = _extract_period_from_counts(counts, n_count, N)
        if r is None:
            steps.append(f"Period extraction failed for a={a_try} — trying next a")
            continue

        steps.append(f"Step 5: Period extracted via continued fractions: r={r}")

        if r % 2 != 0:
            steps.append(f"r={r} is odd — trying next a")
            continue

        factor1 = math.gcd(pow(a_try, r // 2) - 1, N)
        factor2 = math.gcd(pow(a_try, r // 2) + 1, N)
        steps.append(f"Step 6: Compute gcd(a^(r/2) ± 1, N) = ({factor1}, {factor2})")

        if factor1 * factor2 == N and factor1 > 1 and factor2 > 1:
            steps.append(f"✅ FACTORED: {N} = {factor1} × {factor2}")
            steps.append("🔑 ECDH private key derivable from public key on a real quantum computer!")
            runtime = time.perf_counter() - start
            return {
                "N": N,
                "a": a_try,
                "success": True,
                "factors": [factor1, factor2],
                "period": r,
                "qubit_count": qc.num_qubits,
                "circuit_depth": qc.depth(),
                "shots": 1024,
                "top_measurements": top5,
                "circuit_diagram": circuit_diagram,
                "steps": steps,
                "runtime_seconds": round(runtime, 4),
                "quantum_note": (
                    f"QFT found period r={r} for a={a_try}. "
                    f"A real error-corrected quantum computer would need "
                    f"~2,330 logical qubits to factor a 256-bit number (Roetteler 2017). "
                    f"AerSimulator classically simulates {qc.num_qubits} qubits."
                ),
            }

        steps.append(f"Factor extraction failed for a={a_try}")

    runtime = time.perf_counter() - start
    return {
        "N": N,
        "a": candidates_a[0],
        "success": False,
        "factors": None,
        "period": None,
        "qubit_count": n_count + 4,
        "circuit_depth": "variable",
        "shots": 1024,
        "top_measurements": {},
        "circuit_diagram": circuit_diagram,
        "steps": steps + ["All a candidates exhausted — retry or use classical simulation"],
        "runtime_seconds": round(runtime, 4),
        "quantum_note": "Shor's algorithm is probabilistic. Multiple runs may be needed.",
    }
