# CryptoProject v2.2.0

A modular C++20 learning project that brings together standard cryptographic demonstrations,
small educational cryptosystems, defensive validation, a classical quantum state-vector simulator,
optional CUDA compute kernels, and integrated experiment reports. The intended IDE is **CLion**;
the Windows compiler toolchain is **MSVC** and the build generator is **Ninja**.

> **Security notice:** this is an educational project, not a production cryptographic library.
> Do not use its custom cryptographic implementations to protect real data, accounts, or communications.

## 1. Development environment

- IDE: CLion (Visual Studio IDE is not required).
- Windows compiler: MSVC from Visual Studio Build Tools.
- Build system: CMake 3.27 or newer; Ninja is used by the included presets.
- Language standard: C++20.
- Big integers: Boost.Multiprecision (Boost 1.80 or newer).
- GPU: optional NVIDIA CUDA Toolkit. The CMake configuration falls back to CPU when CUDA is absent.
- Randomness: platform operating-system CSPRNG (`BCryptGenRandom` on Windows and `getrandom` on Linux).

The selected CUDA Toolkit must support the installed MSVC toolset. NVIDIA's current Windows guide
lists supported compiler families by toolkit release; do not assume that every CUDA release supports
every MSVC version. See the [NVIDIA CUDA Windows installation guide](https://docs.nvidia.com/cuda/cuda-installation-guide-microsoft-windows/).

## 2. Top-level program modes

1. **CryptoSetAnalysis** — run the three requested cryptosystems independently, compare their measured operation times, and estimate Grover/Shor resources for the applicable components.
2. **IntegratedCryptoAnalysis** — execute all three independent sets in one batch and aggregate their resource and time reports. This is an analysis aggregator, not a hybrid cipher that merges all keys.
3. **Primitive diagnostics / educational examples** — low-level SHA-256, AES-GCM, RSA, P-256 and ML-KEM demos. These are component diagnostics, not the three crypto-set workflows above.
4. **CryptoAnalyzer** — known-answer tests and basic public-key policy checks for standard algorithms; controlled analysis of self-generated educational instances.
5. **QuantumAttack Simulator** — CPU state-vector simulation, selected CUDA gate kernels, Grover, QFT, tiny Shor order-finding, and resource illustrations.
6. **Educational Integrated Analysis** — legacy toy-instance demonstrations and analyzer comparisons.
7. **Benchmark** — repeated SHA-256 CPU timing with detailed and summary CSV output.
8. **Compute Engine** — CUDA device discovery in the console menu; the C++ API exposes vector-add, short-message SHA-256 batch, and selected state-vector CUDA operations.

## 3. Standard cryptographic algorithms (primitive-level diagnostics)

| Algorithm | Included functionality | Important qualification |
|---|---|---|
| SHA-256 | Hashing and MGF1-SHA-256 | Custom implementation; limited KAT coverage |
| AES-128-GCM | Authenticated encryption and decryption | Custom implementation; nonce discipline remains important |
| RSA | Key generation, RSAES-OAEP-SHA-256, RSASSA-PSS-SHA-256 | Variable-time Boost.Multiprecision arithmetic |
| NIST P-256 | ECDH and ECDSA with SHA-256 | Variable-time arithmetic; ECDH returns raw shared x-coordinate without a KDF |
| ML-KEM-768 | Portable in-tree C++ key generation, encapsulation, and decapsulation | Implements the FIPS 203 ML-KEM-768 parameter set; not NIST ACVP validated or independently audited |

The interactive RSA demonstration requests a 4096-bit modulus. Smaller RSA sizes are only used by
smoke tests and are not security recommendations. P-256 ECDH currently returns the raw shared
x-coordinate; a real protocol must apply a suitable KDF and bind the result to its protocol context.

RSA and P-256 are implemented directly in this project. Their arithmetic is straightforward and
variable-time, rather than constant-time hardened code. AES-GCM is also a custom implementation.
The included known-answer tests are useful checks, but they do not constitute independent review,
formal verification, or complete standards conformance.

### ML-KEM-768 status

`CryptoSystem/Standard/ModuleLWE/MLKEM768.cpp` now contains a portable C++ implementation of the
ML-KEM-768 parameter set. It implements Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, SHAKE256,
NTT/inverse NTT, polynomial/vector encoding and compression, K-PKE, and the ML-KEM encapsulation /
decapsulation transforms with implicit rejection. It does not call `BCryptEncapsulate` or
`BCryptDecapsulate`; Windows CNG ML-KEM support is not required. The operating system CSPRNG is still
used to generate fresh key-generation and encapsulation randomness.

The project includes primitive known-answer checks, NTT/polynomial multiplication checks, round-trip
and implicit-rejection tests. During development, the implementation also passed bidirectional
encapsulation/decapsulation interoperability tests against OpenSSL 3.5.5 ML-KEM-768. This is useful
independent interoperability evidence, but it is **not** NIST ACVP validation, a formal verification,
or an independent security audit. Do not use this custom implementation to protect real data until
it has undergone expert review and formal validation. NIST's FIPS 203 publication page currently
records a planning note about an issue to be corrected in a future revision; review the current
[official publication and errata](https://csrc.nist.gov/pubs/fips/203/final) before standards work.

## 4. CryptoSetAnalysis and IntegratedCryptoAnalysis

The project deliberately has two separate top-level folders for the requested workflow:

- `CryptoSetAnalysis/` contains three independent cryptosystem runners and their individual quantum-attack reports.
- `IntegratedCryptoAnalysis/` runs the same three independent runners in one batch and aggregates their operation times and quantum resource ledgers. It does not combine the algorithms into one hybrid encryption construction.

### Set 1 — AES-SHA-ECDSA

- Key establishment: P-256 ECDH.
- Sender authentication: P-256 ECDSA signature.
- Key derivation and message digest: HKDF-SHA-256 / SHA-256.
- Payload encryption: AES-128-GCM.

ECDSA is a signature algorithm; ECDH is the P-256 key-agreement operation used to establish the shared secret.

### Set 2 — AES-SHA-RSAPSS

- Key transport: RSA-OAEP-SHA-256 transports a fresh 32-byte secret.
- Sender authentication: RSA-PSS-SHA-256 signature.
- Key derivation and message digest: HKDF-SHA-256 / SHA-256.
- Payload encryption: AES-128-GCM.

RSA-PSS is a signature scheme, not a key-agreement scheme. RSA-OAEP is used for the key-transport step. In this educational runner the same RSA key pair is used for the OAEP and PSS operations to keep the comparison compact; real protocols should use separate RSA key pairs for encryption/key transport and signing.

### Set 3 — SHA-AES-MLKEM

- Key establishment: ML-KEM-768 encapsulation/decapsulation.
- Key derivation and message digest: HKDF-SHA-256 / SHA-256.
- Payload encryption and integrity: AES-128-GCM.
- No sender digital signature is included in this set. The GCM tag authenticates ciphertext integrity, but it does not by itself identify the sender.

Each set generates its own secret, derives its own AES key, encrypts/decrypts the same input message, and records operation times. The individual comparison reports include key generation, key establishment, SHA-256, HKDF, AES encryption/decryption, and signature generation/verification where the set has signatures.

### Quantum attack/resource reporting

- **Grover / AES-128:** ideal unstructured key-search query estimate is approximately `(pi/4) * 2^64` iterations. A separate illustrative time is shown assuming 1 microsecond per logical iteration; that assumed iteration duration is not a hardware measurement.
- **Grover / SHA-256 preimage:** the generic 256-bit preimage model is approximately `(pi/4) * 2^128` iterations. This is a preimage model, not a SHA-256 collision estimate.
- **Shor / P-256:** Shor applies in principle to the elliptic-curve discrete-log problem underlying P-256 ECDH/ECDSA. The displayed `3*n+1` logical-register figure is a coarse register illustration only.
- **Shor / RSA:** Shor applies in principle to factoring the RSA modulus. The displayed register figure is likewise a coarse register illustration only.
- **ML-KEM-768:** Shor's factoring/discrete-log algorithm is not a direct attack on Module-LWE. This project does not fabricate a quantum resource estimate for a Module-LWE break. Grover figures in this set refer to its AES-128/SHA-256 components only.

The existing simulator runs only tiny educational examples (Grover on a 3-qubit register and Shor on `N=15`). Their measured milliseconds are classical state-vector simulation times, not attack times against full-size cryptography. Full-size Shor wall-clock times are not estimated because this project does not model a fault-tolerant quantum computer, logical gate throughput, error correction, or gate counts.

### Output folders

- `Output/CryptoSetAnalysis/`: individual set reports, CSV metrics, and the three-way separate-set comparison.
- `Output/IntegratedCryptoAnalysis/`: one combined text report and CSV ledger with summed operation times, peak per-set time, Grover iteration totals, and Shor register resource totals/peak.

## 5. Educational CryptoSystem

All educational instances are deliberately small and insecure. They are generated by this program;
the analyzer is intended for these controlled examples, not arbitrary deployed systems.

| Algorithm | Educational construction |
|---|---|
| Toy RSA | 16-32-bit modulus; default 32-bit |
| Toy ECC | Curve `y^2 = x^3 + 2x + 3 (mod 97)`, base point `(0,10)`, subgroup order 50 |
| Toy Module-LWE | `R_q = Z_257[x]/(x^4+1)`, ring degree `n=4`, module rank `k=2`, secret/error coefficients `{-1,0,1}` |
| Toy AES keyspace | Actual AES-128-GCM primitive with only 4-16 key bits unknown; remaining key bits fixed to zero |
| Truncated SHA-256 | First 4-16 bits of the SHA-256 output for collision demonstrations |

The educational Module-LWE model uses polynomial multiplication modulo `x^4+1` and a rank-2 module.
It is a tiny teaching construction, not ML-KEM and not a security parameter set. The legacy name `ToyLwe*`
remains in some C++ type/function identifiers; its secret data shape is now two polynomials of four
coefficients each, and the mathematical model is Module-LWE as described above.

The AES experiment does not reduce the AES primitive to a smaller cipher. It fixes most of an
AES-128 key to zero and searches only a deliberately restricted 4-16-bit keyspace. The SHA exercise
truncates the output space; it does not demonstrate a collision in full SHA-256. The ECC curve and
Module-LWE parameters are currently fixed rather than user-configurable; only the RSA modulus, AES
unknown-key bits, and truncated SHA output width are selected in the current menu.

## 6. CryptoAnalyzer

- Standard mode runs the included SHA-256 empty-message and AES-128-GCM example known-answer checks.
- A basic RSA public-key policy helper evaluates key parameters and a configurable-in-code size rule.
- Educational mode analyzes the application's generated toy RSA, ECC, Module-LWE, and restricted-keyspace AES instances.
- The standard analyzer is not a broad vulnerability scanner, key-recovery system, certification,
  or complete cryptographic conformance suite.

## 7. QuantumAttack simulator

The simulator is classical software that stores `2^n` complex amplitudes. Memory use grows
exponentially with the number of simulated qubits. The default state-vector limit is 22 qubits;
small Shor experiments enforce a much smaller register limit.

Included operations and demonstrations:

- X, Z, Hadamard, CNOT, phase marking, diffusion, and controlled basis-state permutations.
- Probability extraction and reproducible pseudo-random measurement shots.
- Small Grover search and a direct state-vector QFT transform.
- A tiny Shor-style order-finding experiment restricted to odd composite inputs no larger than 15.
- Educational superposition, entanglement, interference, measurement, Grover, QFT, and Shor walkthroughs.
- An illustrative cryptographic resource model and CSV quantum experiment reports.

The state-vector qubit count, gate counter, operation-depth counter, CPU elapsed time, and memory
are simulator quantities. The resource model is illustrative: it omits reversible circuit decomposition,
work ancillas, error correction, fault tolerance, routing, and hardware overhead. It does not estimate
a practical RSA-4096 or P-256 break, and it does not use quantum hardware.

## 8. ComputeEngine and CUDA

CUDA is optional. The project includes CPU fallback and the following CUDA-capable paths:

- GPU discovery and device-property reporting.
- CPU/GPU vector addition and multi-GPU workload distribution through the C++ API.
- Multi-GPU distribution weighted by the reported multiprocessor counts; no GPU-to-GPU result
  cross-validation is performed.
- A CUDA SHA-256 batch kernel for messages of at most 55 bytes (single SHA-256 block). Longer
  messages are rejected by this batch interface; the regular SHA-256 implementation handles general input sizes on CPU.
- CUDA state-vector kernels for Hadamard, basis-state phase flip, and diffusion. They are exposed as
  explicit simulator methods; the current menu's ordinary Grover/QFT/Shor experiment routines use
  the CPU state-vector path unless the GPU-specific methods are called directly by a C++ caller.

GPU kernel time, transfer time, and initialization time are kept separately from end-to-end wall time.
CUDA source files are only included when CMake detects a usable CUDA compiler and toolkit. The
archive was not compiled with CUDA in the previous CPU-only environment; treat CUDA compilation and
GPU execution on the target PC as pending local verification.

## 9. Educational integrated mode and performance reports

Integrated mode performs these educational operations:

- Toy RSA generation and analyzer comparison.
- Toy ECC generation and analyzer comparison.
- Toy Module-LWE generation and analyzer comparison.
- Restricted-keyspace AES-128-GCM generation and analyzer comparison.
- A tiny Shor-style simulation on a small composite input.
- A truncated SHA-256 collision demonstration.
- Additional superposition, entanglement, interference, Grover, and QFT demonstrations.

Reports are written under `Output/`, including performance CSVs and the quantum experiment report.
The benchmark menu currently measures CPU SHA-256 over a 1 MiB payload for five repetitions;
it is not yet a comprehensive comparative CPU/GPU benchmark suite.

`PerformanceMonitor` records wall time using `std::chrono::steady_clock`, process CPU time using
`std::clock` (not per-thread CPU time), and optional GPU timing fields supplied by CUDA APIs.

## 10. Build in CLion on Windows

1. Extract the project archive.
2. Open the top-level `CryptoProject` folder in CLion.
3. In **Settings > Build, Execution, Deployment > Toolchains**, select the MSVC toolchain.
4. Ensure CMake and Ninja are available to CLion.
5. In **Settings > Build, Execution, Deployment > CMake**, select `msvc-ninja-debug`.
6. Reload the CMake project and build the `CryptoProject` target.

Use `msvc-ninja-release` for release-mode CPU timing. Use `cpu-only-debug` to disable CUDA explicitly.
The included presets do not hard-code the MSVC version or CUDA architecture.

### CPU-only command-line build

Open a terminal with the desired compiler environment and run:

```powershell
cmake --preset cpu-only-debug
cmake --build --preset build-cpu-only
ctest --test-dir build/cpu-only-debug --output-on-failure
```

### CUDA-enabled command-line build

```powershell
cmake --preset msvc-ninja-debug
cmake --build --preset build-debug
ctest --preset test-debug
```

If CUDA compiler/toolkit detection fails and `CRYPTO_REQUIRE_CUDA` is `OFF`, CMake configures the
CPU-only paths. To require CUDA, set `CRYPTO_REQUIRE_CUDA=ON` at configure time.

## 11. Source layout

```text
CryptoProject/
├── CMakeLists.txt
├── CMakePresets.json
├── main.cpp
├── Common/
├── ComputeEngine/
│   ├── CUDA/
│   └── ComputeEngine.*
├── CryptoSystem/
│   ├── Standard/
│   └── Educational/
├── CryptoAnalyzer/
│   ├── Standard/
│   └── Educational/
├── CryptoSetAnalysis/
│   └── Sets/ (AES-SHA-ECDSA, AES-SHA-RSAPSS, SHA-AES-MLKEM)
├── IntegratedCryptoAnalysis/
├── QuantumAttack/
│   ├── Standard/
│   ├── Educational/
│   └── Reports/
├── IntegratedMode/ (legacy toy educational integrated analysis)
├── Benchmark/
├── Tests/
├── docs/
└── Output/
```

## 12. Test status

Six CTest targets are included: `CommonSmokeTests`, `ComputeEngineSmokeTests`, `ProjectSmokeTests`,
`QuantumSmokeTests`, `MLKEM768SmokeTests`, and `CryptoSetAnalysisSmokeTests`. The current source was configured and built in a
CPU-only Linux environment with GCC 14.2; all six tests passed. A separate
bidirectional interoperability check against OpenSSL 3.5.5 ML-KEM-768 also passed. The uploaded
Windows/MSVC + CUDA 13.5 environment was not available for direct verification in this workspace;
rebuild and run the tests locally in CLion. CUDA was disabled for the current build.

See `docs/ALGORITHM_STATUS.md` and `docs/THEORETICAL_REVIEW.md` for the precise status and known limitations.

## Security notes

The RSA and P-256 arithmetic is variable-time and has not been independently audited. The custom
AES-GCM, SHA-256, RSA, and P-256 code is provided for algorithm study, not production deployment.
Use a vetted cryptographic library for real data. All program output, log messages, source comments,
and test messages are written in English.
