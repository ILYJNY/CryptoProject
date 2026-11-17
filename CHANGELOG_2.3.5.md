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

## Not implemented in this release

- The Shor circuits for Toy ECC (elliptic-curve discrete logarithm) and for Toy RSA (factoring the
  generated modulus). Their reports are theory only: `Circuit implemented: NO`,
  `Attack outcome: NOT ATTEMPTED`. No ECC scalar and no RSA factor is recovered by a quantum method.
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
