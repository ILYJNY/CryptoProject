# Changelog

## 2.3.5

- Added `EducationalQuantumAttack/`: independent quantum-attack analysis of the three educational sets on their real toy parameters. Simulated circuits: Grover (Toy AES, Toy SHA preimage) and Brassard-Hoyer-Tapp (Toy SHA collision). Toy ECC and Toy RSA are matched with Shor but are theory only (circuits not implemented); Toy Module-LWE is NOT MODELED.
- Added `IntegratedEducationalQuantumAttack/`: runs the three independent analyses and compares them without merging the cryptosystems or summing estimated attack times.
- Reports keep quantum simulator runtime, estimated quantum attack time and classical attack runtime apart, and write missing values as NOT MODELED / NOT EXECUTED instead of 0.
- QuantumAttack 2.8: single-qubit phase shift and mid-circuit measurement added to the simulator.
- See `CHANGELOG_2.3.5.md`, `README_2.3.5.md` and `QUANTUM_ATTACK_DESIGN.md`. Earlier 2.3.x notes are in `CHANGELOG_2.3.0.md` to `CHANGELOG_2.3.4.md`.

## 2.2.0

- Added `CryptoSetAnalysis/` with three separately runnable and comparable cryptosystem sets: AES-SHA-ECDSA, AES-SHA-RSAPSS, and SHA-AES-MLKEM.
- Added `IntegratedCryptoAnalysis/` to execute the three independent sets in one batch and aggregate measured operation time and quantum-resource estimates; this is an analysis aggregator, not a hybrid cipher.
- Added per-set and integrated TXT/CSV reports under `Output/CryptoSetAnalysis/` and `Output/IntegratedCryptoAnalysis/`.
- Added Grover estimates for AES-128 key search and SHA-256 preimage search, plus qualified Shor applicability/resource illustrations for P-256 and RSA.
- Added 3-qubit Grover and N=15 Shor toy-simulator timings, clearly separated from full-size attack estimates.
- Added `CryptoSetAnalysisSmokeTests`; the complete six-target CPU test suite passes in GCC 14.2.
- Windows/MSVC and CUDA 13.5 builds have not been directly verified in this environment.

## 2.1.0

- Replaced the Windows CNG ML-KEM-768 wrapper with a portable in-tree C++ implementation.
- Added Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, and SHAKE256 primitives for ML-KEM.
- Added ML-KEM-768 NTT/inverse NTT, polynomial/vector encoding and compression, K-PKE, key generation,
  encapsulation, decapsulation, and implicit rejection.
- Added `MLKEM768SmokeTests` covering primitive known-answer checks, NTT multiplication, round-trip,
  invalid-ciphertext implicit rejection, and decapsulation-key integrity validation.
- Verified CPU-only build and five CTest targets with GCC 14.2 / CMake 3.31.6; separately verified
  bidirectional interoperability with OpenSSL 3.5.5 ML-KEM-768.
- MSVC/CLion and CUDA 13.5 execution on the target Windows machine remain to be locally verified.
- The custom implementation is not NIST ACVP validated or independently audited; not production-ready.

## 2.0.0

- Consolidated the prior CryptoProject source modules into one CMake/C++20 project.
- Kept Standard and Educational cryptography paths separate.
- Added a true polynomial-ring toy Module-LWE teaching model over `Z_257[x]/(x^4+1)` with rank 2.
- Added/retained CUDA vector-add, short-message SHA-256 batch, and selected quantum state-vector kernels.
- Expanded the theoretical review and capability/verification status documentation.

## 2.2.1

- Made the estimated time-to-compromise figure explicit and prominent in individual set output, three-set comparison output, and integrated analysis output.
- Clearly separated measured cryptosystem operation time, measured tiny Grover/Shor simulator runtime, and scenario-estimated full-parameter attack time.
- Added an explicit CSV metric for estimated time to compromise each modeled set.
- ML-KEM-768 whole-set break time is displayed as NOT ESTIMABLE while its Module-LWE attack cost remains unmodeled; AES-only Grover is labeled component-only.
- Clarified that the three separate set estimates are shown individually and are not summed into a misleading single elapsed time.
- CPU build and CTest verification recorded separately from Windows/MSVC/CUDA target-platform verification.
