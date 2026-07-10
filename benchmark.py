import time
import statistics
from crypto.ecdhe import generate_ecdhe_keypair, ecdhe_compute_shared
from crypto.kyber import KyberKEM
from crypto.dilithium import DilithiumSigner

ITERATIONS = 100

def benchmark(name, func, *args, **kwargs):
    times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        func(*args, **kwargs)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms
    
    avg_time = statistics.mean(times)
    print(f"{name:.<40} {avg_time:.3f} ms")
    return avg_time

def run_benchmarks():
    print(f"Running benchmarks ({ITERATIONS} iterations each)...\n")
    
    print("--- ECDHE (P-256) ---")
    benchmark("Key Generation", generate_ecdhe_keypair)
    priv_a, pub_a = generate_ecdhe_keypair()
    priv_b, pub_b = generate_ecdhe_keypair()
    benchmark("Compute Shared Secret", ecdhe_compute_shared, priv_a, pub_b)
    print(f"Public Key Size: {len(pub_a)} bytes\n")
    
    print("--- Kyber768 (ML-KEM-768) ---")
    kem = KyberKEM()
    benchmark("Key Generation", kem.generate_keypair)
    pub_k, priv_k = kem.generate_keypair()
    benchmark("Encapsulation", kem.encapsulate, pub_k)
    ct, ss_enc = kem.encapsulate(pub_k)
    benchmark("Decapsulation", kem.decapsulate, priv_k, ct)
    print(f"Public Key Size: {len(pub_k)} bytes")
    print(f"Secret Key Size: {len(priv_k)} bytes")
    print(f"Ciphertext Size: {len(ct)} bytes\n")

    print("--- ML-DSA-65 (Dilithium3) ---")
    signer = DilithiumSigner()
    benchmark("Key Generation", signer.generate_keypair)
    pub_d, priv_d = signer.generate_keypair()
    msg = b"Benchmark message for Dilithium signature"
    benchmark("Sign", signer.sign, priv_d, msg)
    sig = signer.sign(priv_d, msg)
    benchmark("Verify", signer.verify, pub_d, msg, sig)
    print(f"Public Key Size: {len(pub_d)} bytes")
    print(f"Secret Key Size: {len(priv_d)} bytes")
    print(f"Signature Size: {len(sig)} bytes\n")

if __name__ == '__main__':
    run_benchmarks()
