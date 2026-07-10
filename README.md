# QuantumCNS (PQChat v2.0)

A Post-Quantum Cryptography chat application (PQChat v2.0) built with Flask and Socket.IO. QuantumCNS provides a secure communication channel that is resistant to quantum computing attacks by leveraging ML-KEM-768 (Kyber) and ML-DSA-65 (Dilithium3), combined with classical ECDHE (P-256) and AES-256-GCM.

The server operates as a **Blind Relay**, meaning it never generates crypto keys, decrypts messages, or inspects payloads.

## Features
- **Post-Quantum Key Encapsulation**: Uses ML-KEM-768 alongside ECDHE for hybrid key exchange.
- **Post-Quantum Digital Signatures**: Uses ML-DSA-65 (Dilithium3) for identity and message authentication.
- **Blind Relay Architecture**: True end-to-end encryption.
- **Quantum Simulation Tools**: Includes simulators for Shor's, Grover's, and Lattice attacks (`simulator/`).

## Prerequisites

Before running the application, ensure you have the following installed:
- **Python 3.9+**
- **liboqs**: The C library for quantum-safe cryptographic algorithms. Since the project uses `liboqs-python`, the underlying C library must be present.
  - **macOS (Homebrew)**: `brew install liboqs`
  - **Linux (Debian/Ubuntu)**: `sudo apt install liboqs-dev` (If unavailable in your package manager, [build from source](https://github.com/open-quantum-safe/liboqs)).

## Installation

1. **Navigate to the project directory:**
   ```bash
   cd /path/to/QuantumCNS
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   
   # On macOS/Linux:
   source .venv/bin/activate
   
   # On Windows:
   .venv\Scripts\activate
   ```

3. **Install the required Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. **Start the Flask-SocketIO Server:**
   ```bash
   python app.py
   ```
   *Note: The SQLite database (`users.db`) and demo users (`alice`, `bob`) will be automatically initialized on startup.*

2. **Access the Application:**
   Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## Running Benchmarks

You can benchmark the cryptographic algorithms (ECDHE, Kyber768, and Dilithium3) to evaluate their performance overhead:

```bash
python benchmark.py
```

## Running Tests

The project uses `pytest` for unit and integration testing. To run the tests (which cover end-to-end functionality, crypto operations, and handshake flows):

1. **Ensure `pytest` is installed** (it may be installed in your environment, or you can install it manually):
   ```bash
   pip install pytest pytest-flask
   ```

2. **Execute the test suite:**
   ```bash
   pytest
   ```
