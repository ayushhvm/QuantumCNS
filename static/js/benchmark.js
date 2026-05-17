import { MlKem768 } from "https://esm.sh/@noble/post-quantum@0.2.0/ml-kem";

export async function runCryptoBenchmark(logFn, iterations = 100) {
    logFn("info", `Starting Benchmark (${iterations} iterations)...`);
    
    // 1. Classical ECDH P-256 Key Generation
    const ecdhStart = performance.now();
    for(let i=0; i<iterations; i++) {
        await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey", "deriveBits"]
        );
    }
    const ecdhEnd = performance.now();
    logFn("info", `[Classical] ECDH P-256 KeyGen: ${(ecdhEnd - ecdhStart).toFixed(2)}ms`);

    // 2. Post-Quantum ML-KEM-768 Key Generation
    const kemStart = performance.now();
    for(let i=0; i<iterations; i++) {
        MlKem768.keygen();
    }
    const kemEnd = performance.now();
    logFn("info", `[Post-Quantum] ML-KEM-768 KeyGen: ${(kemEnd - kemStart).toFixed(2)}ms`);

    // Setup for Derivation/Encapsulation test
    const aliceEcdh = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey", "deriveBits"]
    );
    const bobEcdh = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey", "deriveBits"]
    );
    const aliceKem = MlKem768.keygen();

    // 3. Classical ECDH Derivation
    const ecdhDeriveStart = performance.now();
    for(let i=0; i<iterations; i++) {
        await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: bobEcdh.publicKey },
            aliceEcdh.privateKey,
            256
        );
    }
    const ecdhDeriveEnd = performance.now();
    logFn("info", `[Classical] ECDH Secret Derivation: ${(ecdhDeriveEnd - ecdhDeriveStart).toFixed(2)}ms`);

    // 4. Post-Quantum ML-KEM Encapsulation + Decapsulation
    const kemEncapStart = performance.now();
    for(let i=0; i<iterations; i++) {
        const { ciphertext, sharedSecret } = MlKem768.encapsulate(aliceKem.publicKey);
        MlKem768.decapsulate(ciphertext, aliceKem.secretKey);
    }
    const kemEncapEnd = performance.now();
    logFn("info", `[Post-Quantum] ML-KEM Encap+Decap: ${(kemEncapEnd - kemEncapStart).toFixed(2)}ms`);
    
    logFn("info", "Benchmark Complete.");
}
