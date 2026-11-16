# Algorithm and feature status — CryptoProject v2.1.0

| Area | Status | Scope and qualification |
|---|---|---|
| SHA-256 | Implemented | Custom implementation; included KAT set is limited |
| AES-128-GCM | Implemented | Custom implementation; NIST example vector included |
| RSA | Implemented | RSAES-OAEP-SHA-256 and RSASSA-PSS-SHA-256; menu uses 4096-bit modulus; variable-time arithmetic |
| P-256 ECDH | Implemented | Raw shared x-coordinate returned; no KDF included |
| P-256 ECDSA | Implemented | SHA-256 digest; variable-time arithmetic |
| ML-KEM-768 | Portable in-tree C++ implementation | ML-KEM-768 parameter set; SHA3/SHAKE, NTT, K-PKE, KEM and implicit rejection; not NIST ACVP validated or audited |
| Toy RSA | Implemented | Self-generated 16-32-bit modulus instances |
| Toy ECC | Implemented | Curve over F_97; base point has order 50 |
| Toy Module-LWE | Implemented in v2.0 | R_q = Z_257[x]/(x^4+1), n=4, k=2; 3^8 small secret candidates; not ML-KEM |
| Toy AES keyspace | Implemented | Actual AES-128-GCM primitive with 4-16 unknown bits |
| Truncated SHA-256 | Implemented | Collision demo with 4-16 digest bits, not full SHA-256 collision |
| Quantum state vector | Implemented | Classical CPU simulation; default limit 22 qubits |
| Quantum gates | Implemented | X, Z, H, CNOT, phase marking, diffusion, controlled permutations |
| Grover demonstration | Implemented | Small state-vector search, CPU path |
| QFT demonstration | Implemented | Direct state-vector transform, limited educational size |
| Shor demonstration | Implemented as a tiny model | Odd composite inputs up to 15; educational order-finding only |
| Quantum resource model | Illustrative only | Omits ancillas, gate decomposition, error correction, fault tolerance, and hardware overhead |
| CPU ComputeEngine | Implemented | Multithreaded vector-add workload |
| CUDA GPU discovery | Conditional | Device properties exposed through CUDA runtime |
| CUDA vector add | Conditional | GPU path and multi-GPU chunk distribution through ComputeEngine API |
| CUDA short SHA-256 batch | Conditional | Single-block kernel, input messages limited to 55 bytes; exposed through ComputeEngine API |
| CUDA quantum kernels | Conditional low-level API | Hadamard, phase flip, diffusion; ordinary experiment helpers still use CPU simulator path |
| Benchmark | Limited | CPU SHA-256 over 1 MiB, five repetitions |
| Standard analyzer | Limited | SHA-256/AES KATs and a basic RSA size policy helper; not comprehensive auditing |
| Educational analyzer | Implemented | Intended for self-generated toy instances only |
| Integrated mode | Implemented | Toy crypto analysis, held-back ground-truth comparison, tiny Shor and educational quantum reports |

## Theoretical notes

- The educational Module-LWE construction was corrected from the earlier ordinary matrix-LWE toy
  model. The v2.0 code now multiplies polynomials in `Z_257[x]/(x^4+1)` and uses a rank-2 module.
- The base point `(0,10)` on `y^2 = x^3 + 2x + 3 (mod 97)` has order 50. The curve group has 100
  points including the point at infinity. This remains a very small educational group.
- SHA-256 single-block padding supports message lengths from 0 through 55 bytes. The CUDA batch
  function deliberately rejects longer strings; this is an interface limitation, not a change to
  the SHA-256 algorithm itself.
- The state-vector simulator stores `2^n` complex amplitudes, so storage and direct state operations
  scale exponentially with simulated qubit count.
- The Shor teaching routine uses a small controlled modular-permutation model and direct QFT state
  transformation. It is not a physical-device circuit compilation or a scalable implementation.

## Verification history and remaining work

Current source verification: CPU-only CMake/Release build under GCC 14.2 and CMake 3.31.6; all five
CTest targets passed, including the new ML-KEM-768 smoke tests. A separate bidirectional
interoperability check against OpenSSL 3.5.5 ML-KEM-768 passed. This is not a substitute for NIST
ACVP validation or an independent audit.

Not verified in the current delivery:

- MSVC compilation inside CLion on the target Windows machine.
- CUDA compilation or execution on an NVIDIA GPU.
- NIST ACVP validation and full FIPS 203 known-answer test coverage for ML-KEM-768.
- Full RSA-4096 key-generation performance and extensive RSA/P-256/AES conformance vectors.
- Constant-time behavior, side-channel resistance, independent security audit, or production security.

A test pass would not establish cryptographic security. The custom RSA, P-256, and AES-GCM routines
are educational demonstrations only.
