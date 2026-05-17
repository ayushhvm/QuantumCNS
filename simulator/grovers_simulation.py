"""
Grover's algorithm impact analysis on symmetric cryptography.

Grover's algorithm provides a quadratic speedup on unstructured search.
For a k-bit symmetric key: classical = 2^k, quantum = 2^(k/2) operations.
This has NO impact on the structure of keys — only on brute-force search speed.

References:
  - Grover, L. (1996). "A fast quantum mechanical algorithm for database search."
  - NIST IR 8105: "Report on Post-Quantum Cryptography" (2016)
  - Bernstein & Lange: "Post-quantum cryptography" (Nature 2017)
"""


def analyze_grovers_impact() -> list[dict]:
    """
    Analyze Grover's algorithm impact on all symmetric primitives used in PQChat.

    NIST post-quantum security requirement: ≥ 128-bit quantum security minimum.
    AES-256 with Grover's gives 2^128 quantum security — passes NIST requirement.

    Returns:
        List of analysis dicts, one per algorithm.
    """
    algorithms = [
        {
            "name": "AES-128",
            "key_bits": 128,
            "used_in_project": False,
            "note": "Not used in PQChat — shown for comparison only",
        },
        {
            "name": "AES-256-GCM (session encryption)",
            "key_bits": 256,
            "used_in_project": True,
            "note": "Used for all message encryption in PQChat v2",
        },
        {
            "name": "SHA-256 (HKDF salt + fingerprints)",
            "key_bits": 128,  # collision: birthday=2^128, preimage=2^256
            "used_in_project": True,
            "note": (
                "Collision via BHT algorithm: classical=2^128, quantum=2^85. "
                "Preimage: classical=2^256, quantum=2^128. "
                "Usage in PQChat (salt + fingerprint) only needs preimage resistance."
            ),
        },
        {
            "name": "HKDF-SHA256 (key derivation)",
            "key_bits": 256,
            "used_in_project": True,
            "note": "Output key is 256 bits; Grover reduces effective strength to 128 bits",
        },
    ]

    results = []
    for alg in algorithms:
        k = alg["key_bits"]
        quantum_security = k // 2

        # NIST threshold: 128-bit post-quantum security
        pq_safe = quantum_security >= 128

        results.append({
            "algorithm":               alg["name"],
            "key_bits":                k,
            "classical_security":      f"2^{k} operations",
            "quantum_security_grover": f"2^{quantum_security} operations",
            "post_quantum_safe":       pq_safe,
            "verdict": (
                "✅ Post-quantum secure (≥ 128-bit quantum security)"
                if pq_safe
                else "⚠️ UPGRADE RECOMMENDED — below 128-bit quantum security threshold"
            ),
            "used_in_project": alg["used_in_project"],
            "note": alg.get("note", ""),
        })

    return results
