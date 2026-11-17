# CryptoProject 2.3.5 — Independent & Integrated Educational Quantum Attack Analysis

## Added

- **`EducationalQuantumAttack/`** — a new, separate module that analyzes each of the three educational
  cryptosystem sets independently against quantum attacks, using the real toy parameters of the set.
  It is not part of `EducationalCryptoSetAnalysis` and does not replace it.
  - Toy AES (AES-128-GCM, 12 unknown key bits): **Grover** search, simulated on the real record. The
    recovered key is verified by AES-GCM and compared with the withheld key.
  - Toy SHA preimage (SHA-256 truncated to 16 bits): **Grover** search with an unknown number of
    solutions (Boyer–Brassard–Høyer–Tapp schedule), simulated on the real digest of the set's message.
  - Toy SHA collision: **Brassard–Høyer–Tapp** collision search, simulated; reported separately from
    the preimage attack and never as plain Grover. Includes the quantum-accessible table memory.
  - Toy ECC: matched with **Shor (ECDLP)**. Resource model only; the circuit is **not implemented**.
  - Toy RSA: matched with **Shor (factoring)**. Resource model only for the real 24-bit modulus; a
    circuit for that modulus is **not implemented**. The existing `N = 15` toy Shor run appears only
    as a separate algorithm-validation experiment.
  - Toy Module-LWE: **NOT MODELED**. Shor is not applied; no qubit, gate, depth or time figure is given.
  - **Message crack-timing**: enter a sentence, encrypt it with each set's 12-bit Toy AES, crack it
    (classical key-space search and Grover), and report the crack times side by side. Menu entry
    `9 -> 5`. Exports `message_crack_report.txt` and `message_crack_metrics.csv`.
- **`IntegratedEducationalQuantumAttack/`** — a new, separate module that runs the three independent
  quantum-attack analyses and compares them: comparison table, CPU/GPU/memory table, aggregates,
  highlights with caveats, applicability, the list of NOT EXECUTED / NOT MODELED items, assumptions
  and limits of interpretation. It does not merge the three cryptosystems and does not sum the
  estimated attack times.
- Three separate time categories in every report: **A** quantum simulator runtime (measured),
  **B** estimated quantum attack time (scenario estimate with stated assumptions), **C** classical
  attack runtime (measured). They are never added together.
- Every number carries its provenance (`measured`, `computed`, `estimated`). A value that does not
  exist is written as `NOT MODELED`, `NOT EXECUTED`, `N/A` or `UNKNOWN`, never as `0`.
- Simulation budget: the state-vector memory is computed before allocation; a circuit outside the
  budget is reported as theory only.
- GPU honesty: an unavailable CUDA backend falls back to the CPU and is labeled as CPU; GPU timings
  appear only when GPU kernels really ran.
- Reports: per-set TXT, metrics CSV and JSON under `Output/EducationalQuantumAttack/`; integrated
  TXT, aggregate CSV, comparison CSV and JSON under `Output/IntegratedEducationalQuantumAttack/`.
- Main menu entries `9. Educational Quantum Attack`, `10. Integrated Educational Quantum Attack`
  and `11. Quantum Simulator Benchmark`. Existing entries 1–8 are unchanged.
- CTest targets `EducationalQuantumAttackTests` and `IntegratedEducationalQuantumAttackTests`.
- Documentation: `README_2.3.5.md`, `QUANTUM_ATTACK_DESIGN.md`.

## Changed (additive; no existing behavior removed)

- `QuantumAttack` 2.8: `QuantumSimulator::apply_phase_shift` and `QuantumSimulator::measure_qubit`
  (mid-circuit measurement with collapse), with the matching CPU backend functions. Existing
  operations are untouched. See `QuantumAttack/CHANGELOG_2.8.md`.
- Educational primitives expose their real parameters and verification predicates:
  `ToyECC` (curve parameters and group law), `ToyAESKeySearch` (candidate key and predicate),
  `ToyModuleLWE` (candidate decoding and predicate), `ToySha256` (message families, prefix overload
  of the collision search, classical preimage search). `analyze_toy_aes`, `analyze_toy_lwe` and
  `find_truncated_sha256_collision` keep their behavior.
- New `CryptoSystem/Educational/EducationalParameters.h` holds the set parameters (12 AES key bits,
  24-bit RSA, 16-bit Toy SHA). `EducationalCryptoSetAnalysis.cpp` now reads these constants instead
  of literals; its results are unchanged.
- Project version 2.3.4 → 2.3.5.

## Real executed quantum attacks and the EducateAnalysis mode (added in this release)

Earlier revisions of this module reported Shor for the toy ECC and toy RSA components as
resource estimates only. This release adds ACTUAL executed quantum attacks on the state-vector
simulator, and an interactive mode that drives them end to end.

- **`EducateAnalysis` mode (main menu entry 12).** Enter a sentence; each of the three toy
  composites encrypts it and is then really cracked, with every intermediate value printed and
  the crack time split by execution method (Single CPU / Multithreaded CPU / GPU parallel):
  - `Toy-AES_Toy-SHA_Toy-ECDSA`  : Grover (Toy AES, Toy SHA) + **Shor ECDLP** on the toy curve.
  - `Toy-AES_Toy-SHA_Toy-RSAPSS` : Grover (Toy AES, Toy SHA) + **Shor factoring** of the toy modulus.
  - `Toy-AES_Toy-SHA_Toy-MLDSA`  : Grover (Toy AES, Toy SHA) + a **custom Grover secret search**
    on the Module-LWE secret (Shor does not apply to Module-LWE).
  Every attack is executed and every recovered value (AES key, decrypted sentence, preimage,
  curve scalar k with k*G = Q, RSA factors and order, Module-LWE secret) is verified against the
  real instance and printed, together with the ciphertext, nonce, tag, digest, curve points and
  modulus. Exports `educate_analysis_report.txt` and `educate_analysis_metrics.csv`.
- **`Engine/ShorFactoring`** - real integer factoring by iterative (one-control-qubit) quantum
  phase estimation of modular multiplication (n + 1 qubits), continued-fraction order recovery,
  and factor extraction, with multi-base/multi-shot retries. Reliably factors the toy modulus
  (default 16-bit) on the simulator.
- **`Engine/ShorEcdlp`** - real elliptic-curve discrete-logarithm recovery by two-stage phase
  estimation of the point translations +G and +Q, computed by coordinate arithmetic (never using
  the secret) and verified by k*G = Q.
- **`Attacks/ToyModuleLweGroverAttack`** - a real custom Grover search over the 3^8 = 6561
  small-secret candidates (13 qubits); it is explicitly not Shor.
- **Output location fix.** All quantum-attack, message-crack, integrated and EducateAnalysis
  exports now report the ABSOLUTE path actually written, so the files are found regardless of the
  working directory the program was launched from (previously only a relative `Output/...` path
  was printed, which landed under the launch directory - e.g. an IDE build folder - and looked
  "missing").

## Fixed

- Crash (access violation, 0xC0000005) when EducateAnalysis was run with the CUDA multi-GPU
  backend on a machine with fewer than two usable GPUs. The distributed backend assumes a
  power-of-two device set of at least two devices; auto-selecting a single device faulted.
  Backend resolution now treats multi-GPU as available only with two or more devices and
  otherwise falls back to the single-GPU backend (or CPU), never to the faulting path.
- To keep the recovery reliable, the EducateAnalysis **real crack now always runs on a CPU
  backend** (the project's CUDA paths are unverified on hardware). A CUDA selection is used only
  for the opt-in GPU-parallel timing row; the GPU is never exercised unless a CUDA backend is
  explicitly chosen, and a GPU run is never silently replaced by a CPU run.

## Not implemented in this release

- In the `EducationalQuantumAttack` RESOURCE-ANALYSIS view (menu 9), Toy ECC and Toy RSA remain
  theory only, because that view analyzes the large default toy RSA modulus (24-bit, ~73 qubits)
  which does not fit the simulator. The real executed Shor attacks live in the EducateAnalysis
  mode (menu 12), which uses a toy RSA modulus size that genuinely runs (default 16-bit).
- Any quantum attack model for Module-LWE.
- The cost inside the Grover and BHT oracles (reversible AES-GCM, SHA-256, table lookup).
- `Engine/PhaseEstimationEngine` (iterative phase estimation on the two new simulator operations) is
  included and tested at the simulator level, but no attack uses it.

Because of the first two items every set reports the status `PARTIAL`, not `ALL ATTACKS SUCCEEDED`.

## Validation

Performed in a CPU-only Linux environment (no CUDA compiler, no GPU):

- GCC 13.3, Release, CUDA not found → CPU: build succeeded with no warnings from project sources;
  CTest **9/9 passed** (7 existing targets + 2 new targets).
- GCC 13.3, Debug, `CRYPTO_ENABLE_CUDA=OFF`: build succeeded; CTest **9/9 passed**.
- Clang 18.1, Release, `CRYPTO_ENABLE_CUDA=OFF`: build succeeded; CTest **9/9 passed**. Clang reports
  conversion warnings only in pre-existing files (`MLKEM768.cpp`, `AES128GCM.cpp`).
- Standalone `QuantumAttack/` build: `QuantumAttackSmokeTests` passed.
- The two new test programs were additionally run 12 times each without a failure.
- The console menu entries 9 and 10 were exercised end to end and produced their report files.

Not verified: Windows/MSVC compilation of the new code, CUDA compilation, and any GPU execution.
