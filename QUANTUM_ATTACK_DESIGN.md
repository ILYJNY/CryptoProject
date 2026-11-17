# Quantum attack analysis design — CryptoProject 2.3.5

This document describes the two modules added in 2.3.5:

- `EducationalQuantumAttack/` — independent quantum-attack analysis of each educational cryptosystem set.
- `IntegratedEducationalQuantumAttack/` — runs the three independent analyses and compares their results.

Both are separate from the classical analyses (`EducationalCryptoSetAnalysis/`,
`IntegratedEducationalCryptoAnalysis/`) and from the simulator library (`QuantumAttack/`).

> Everything here concerns deliberately tiny teaching parameters. Nothing in this project breaks
> AES-128, SHA-256, P-256, RSA-2048 or ML-KEM-768, and no figure in any report is a time to break a
> real cryptosystem.

## 1. Roles of the modules

| Module | Role |
|---|---|
| `QuantumAttack/` | The engine: a classical state-vector simulator with CPU and CUDA backends, plus generic demos (Grover, QFT, toy Shor on `N <= 15`) and benchmarks. |
| `EducationalQuantumAttack/` | The analysis system: takes the real toy parameters of a set, matches each component with the quantum algorithm that fits its mathematical problem, runs the circuits that are implemented on the engine, and reports what is not implemented. |
| `IntegratedEducationalQuantumAttack/` | Runs the three independent analyses, then compares and aggregates them. It does not merge the cryptosystems. |

The three educational sets remain three independent cryptosystems. Each analysis generates and uses
its own instance; no key, ciphertext or result is shared between sets.

## 2. What is implemented, and what is not

| Component | Mathematical problem | Corresponding algorithm | Status in 2.3.5 |
|---|---|---|---|
| Toy AES (AES-128-GCM, 12 unknown key bits) | unstructured key search | Grover | **circuit simulated** on the real record |
| Toy SHA preimage (SHA-256 truncated to 16 bits) | preimage search | Grover, unknown number of solutions | **circuit simulated** on the real digest |
| Toy SHA collision | collision search | Brassard–Høyer–Tapp (BHT) | **circuit simulated**; never reported as plain Grover |
| Toy ECC (curve over F_97, base point of order 50) | elliptic-curve discrete logarithm | Shor (ECDLP) | **theory only** — the circuit is NOT IMPLEMENTED; formula-based resource estimate |
| Toy RSA (24-bit modulus) | integer factoring | Shor (order finding) | **theory only** — a circuit for the real modulus is NOT IMPLEMENTED; formula-based resource estimate |
| Toy Module-LWE (n = 4, k = 2, q = 257) | Module-LWE | none (Shor does not apply) | **NOT MODELED** — no qubit, gate, depth or time figure |

Consequences that the reports state explicitly:

- No ECC private scalar and no RSA factor is recovered by a quantum method in this release. The
  reports for these two components have `Execution status: THEORY ONLY (NOT EXECUTED)`,
  `Circuit implemented: NO` and `Attack outcome: NOT ATTEMPTED`.
- Each set therefore ends with the status `PARTIAL`, never `ALL ATTACKS SUCCEEDED`.
- The existing toy Shor experiment (`run_shor_toy_experiment(15, 2)`) is run only inside the Toy RSA
  report, under the heading *separate algorithm-validation experiment*. It factors the fixed number
  15. Its success does not change the RSA outcome and is never described as an attack on the
  generated modulus. It is not shown for Toy ECC at all, because integer order finding is not an
  elliptic-curve circuit.

## 3. Real parameters

`CryptoSystem/Educational/EducationalParameters.h` is the single source of the set parameters
(12 unknown AES key bits, 24-bit RSA modulus, 16-bit Toy SHA). The classical
`EducationalCryptoSetAnalysis` and the quantum module both read these constants.

Each set analysis receives a *target* (`AesShaEcdsaTarget`, `AesShaRsaPssTarget`,
`ShaAesMlKemTarget`) produced by the same generators the classical analysis uses
(`generate_toy_aes_sample`, `generate_toy_ecc_sample`, `generate_toy_rsa_sample`,
`generate_toy_lwe_sample`). A target holds the public instance and the withheld ground truth.
Component attacks receive **only the public instance**; the ground truth is used afterwards, and only
to check a recovered value.

The 2.3.4 Toy SHA bindings are carried into the reports: the digest is the AES-GCM associated data in
every set, it selects the toy ECC challenge in set 1 and the toy RSA message representative in set 2,
and it feeds the toy key-derivation hash in set 3. The preimage attack targets exactly that digest.

To expose the real parameters instead of copying them, a few read-only functions were added to the
educational primitives (no existing behavior changed):

- `ToyECC`: `toy_ecc_curve_parameters`, `toy_ecc_base_point`, `toy_ecc_is_on_curve`, `toy_ecc_add`, `toy_ecc_multiply`.
- `ToyAESKeySearch`: `toy_aes_candidate_key`, `toy_aes_candidate_matches` (the predicate the classical search uses).
- `ToyModuleLWE`: `decode_toy_lwe_candidate`, `toy_lwe_candidate_matches` (the predicate the classical search uses).
- `ToySha256`: message families (`toy_sha_family_message`), a prefix overload of the collision search and a classical preimage search.

## 4. The simulated circuits

All three simulated attacks are driven by `Engine/GroverEngine` on top of
`QuantumSimulator` (`apply_hadamard`, `apply_phase_flip`, `apply_diffusion`, `measure_all`).

### 4.1 What is simulated and what is not

- **Simulated exactly:** the search register, every Grover iteration and one measurement per circuit run.
- **Not simulated:** the reversible circuit *inside* the oracle. The oracle acts through its truth
  table. To build that table the program evaluates the real predicate on every candidate classically
  (for example 4096 real AES-GCM verifications). This step exists only because a classical simulator
  needs it; it is timed separately as *simulation-only setup* and is not part of the quantum algorithm.
- A measured candidate is always verified classically with the real predicate; an attack is a
  success only when that verification passes.

### 4.2 Toy AES — Grover

- Search space `N = 2^12`; the oracle marks the keys under which AES-128-GCM authenticates the record.
- One marked key is assumed (`M = 1`): with a 128-bit tag the expected number of other authenticating
  keys is about `(N - 1) * 2^-128`.
- Iterations `R = floor(pi / (4 * asin(sqrt(M/N)))) = 50`. If the measured key fails verification the
  circuit is re-run, then the unknown-count schedule is used.

### 4.3 Toy SHA preimage — Grover with an unknown number of solutions

- Target: the 16-bit Toy SHA digest of the set's message. Search domain: `2^(b+2)` messages of a
  per-set message family `prefix + decimal counter`, which contains 4 preimages on average.
- The attacker does not know how many preimages the domain holds, so the iteration count follows the
  Boyer–Brassard–Høyer–Tapp schedule: draw the count uniformly below a bound that grows by 6/5 after
  each failure and is capped at `sqrt(N)`.
- If a domain contains no preimage the search times out and the domain is enlarged (up to `2^(b+4)`).
- Query complexity: about `(pi/4) * 2^(b/2)`.

### 4.4 Toy SHA collision — Brassard–Høyer–Tapp

1. Classical phase: hash `k = round(2^(b/3))` messages (40 for `b = 16`) into a table.
2. Quantum phase: Grover over a disjoint domain of `2^b` messages for a message whose digest is in
   the table. The expected number of marked messages is `k`, so about `(pi/4) * sqrt(2^b / k)`
   iterations are used (31 for `b = 16`).
3. The measured message and its table partner are two different messages with the same digest.

Total queries are about `2^(b/3)`, against about `2^(b/2)` for the classical birthday search, at the
price of a quantum-accessible table of `k * b` bits. The report states that this memory's hardware
cost is NOT MODELED and that, once it is charged, BHT is not known to beat classical parallel
collision search.

Preimage and collision are two attack kinds with two report sections; their numbers are never merged.

## 5. Resource reporting

Every attack report has two resource sections that are never mixed.

**[1] Circuit executed on the state-vector simulator** — measured: simulated qubits, simulator
operations by type, sequential operation depth, oracle calls. These are simulator operations (one
phase flip per marked state, one native diffusion), not elementary logical gates.

**[2] Logical resource model** — computed or estimated, never executed.

- Grover-type attacks: an explicit construction. The diffusion operator is
  `H^n X^n (C^(n-1) Z) X^n H^n`, the multi-controlled Z being a Toffoli V-chain: `2(n-1) - 3`
  Toffolis and `n - 3` clean ancillas for `n >= 4`. Depth per iteration `2n + 1`. Everything inside
  the oracle is excluded, so these figures are lower bounds, and the oracle's gate count, depth and
  workspace are reported as NOT MODELED together with a statement of what one oracle call contains.
- Shor (factoring): `2n + 3` logical qubits (Beauregard 2003) and the Toffoli interpolation formula
  already used by `CryptoSetAnalysis`, `(64 * (log2 n - 2) + 29.46) * n^3`.
- Shor (ECDLP): `9n + 2*ceil(log2 n) + 10` logical qubits and `448 * n^3 * log2(n) + 4090 * n^3`
  Toffoli gates (Roetteler, Naehrig, Svore, Lauter 2017), also already used by `CryptoSetAnalysis`.
- The Shor formulas were derived for cryptographic sizes. At toy sizes they are extrapolations and
  are labeled as such; they indicate an order of magnitude only.
- Module-LWE: no model. Every field is `NOT MODELED`.

All qubit counts are logical qubits. Error correction and physical qubits are excluded everywhere.

### Provenance of every number

A value is stored as a `Metric` with one of these kinds:

| Kind | Meaning |
|---|---|
| `measured` | observed while running on this computer |
| `computed` | exact count from the executed circuit or a closed formula |
| `estimated` | model or scenario estimate; the assumptions are in the note |
| `NOT MODELED` | no defensible model is implemented |
| `NOT EXECUTED` | would have been measured, but the circuit was not run |
| `N/A` | the quantity does not apply |
| `UNKNOWN` | not available on this platform |

A value that does not exist is printed as its kind, written as text in CSV and as `null` in JSON. It
is never written as `0`.

## 6. The three times

| Category | What it is | How it is obtained |
|---|---|---|
| **A. Quantum simulator runtime** | wall time a classical computer needed to simulate the circuit; the simulation-only setup and the process CPU time are listed next to it | measured |
| **B. Estimated quantum attack time** | time on hypothetical quantum hardware | scenario estimate |
| **C. Classical attack runtime** | the existing classical educational attack on the same instance | measured |

They are printed under separate labels and never added together.

Assumptions behind B (the same scenario rates `CryptoSetAnalysis` uses, editable in
`HardwareScenario`): an idealized, error-free logical quantum computer; 1 microsecond per Grover
iteration (oracle call plus diffusion); 1 microsecond per serially executed logical Toffoli gate.
For Grover-type attacks the oracle's internal circuit is not modeled, so the per-iteration rate is an
assumption rather than a derived value. Error correction, routing, state preparation and measurement
overhead are excluded.

The integrated analysis sums A and C over the attacks that have them and explicitly does **not** sum B.

## 7. Simulation budget and computer resources

- The state-vector memory is computed before anything is allocated: `16 bytes * 2^qubits`, plus a
  working-set factor derived from what the simulator allocates.
- `SimulationBudget` (default 26 qubits, 2 GiB of working memory) decides whether a circuit is run.
  A circuit outside the budget is reported as theory only; it is neither a success nor a failure.
- Per attack the report lists the backend requested and used, CPU threads, state-vector bytes, the
  modeled working memory, the process peak memory (a process-wide high-water mark, so an upper bound
  for a single attack), and the GPU fields.
- GPU honesty: if a CUDA backend is requested but unavailable, the circuits run on the CPU, the
  report labels the backend as CPU and states `UNAVAILABLE`. GPU kernel and transfer times are shown
  only when GPU kernels really ran; otherwise they are `N/A`.

## 8. Status and failure propagation

- Attack outcome: `SUCCEEDED` (recovered and classically verified), `FAILED` (executed without a
  verified result), `NOT ATTEMPTED` (not executed or not modeled).
- Set status: `FAILED` if any executed attack failed or raised an error; `ALL ATTACKS SUCCEEDED` only
  if every attack was executed and succeeded; `PARTIAL` otherwise.
- Integrated status: `FAILED` if any set failed, also when a set's own status is stale and only the
  attack records the failure; `ALL ATTACKS SUCCEEDED` only if every set is; `PARTIAL` otherwise.

## 9. Integrated analysis

`IntegratedEducationalQuantumAttack` produces:

- a comparison table (one row per attack): execution status, outcome, simulated qubits, model
  qubits, model gates, model depth, oracle calls, and the three times in three columns;
- a CPU / GPU / memory table;
- aggregates: total simulator runtime, total simulation-only setup, total classical runtime;
- highlights with caveats: smallest resource model, smallest modeled depth, fastest simulator run,
  smallest executed circuit;
- the applicability of each attack model, the list of NOT EXECUTED / NOT MODELED items, the
  de-duplicated assumptions and the limits of interpretation.

It does not rank the systems by "which falls first" and does not report a time to break a complete
cryptosystem: the attack models include and exclude different costs.

## 10. Engine additions (QuantumAttack 2.8)

Two operations were added to `QuantumSimulator` without changing any existing operation:

- `apply_phase_shift(target, angle)` — the single-qubit gate `diag(1, e^{i*angle})`;
- `measure_qubit(target, uniform_sample)` — a mid-circuit projective measurement with collapse.

Both run on the CPU reference path; with a CUDA backend selected they are counted as CPU fallback
operations. `Engine/PhaseEstimationEngine` builds iterative phase estimation on them. It is covered
by a simulator-level test (the phases of a cyclic shift). **No attack in this release uses it**: the
Shor circuits that would need it are not implemented.

## 11. Output files

Default directories follow the existing `Output/<Module>/` convention.

```text
Output/EducationalQuantumAttack/
├── aes_sha_ecdsa_quantum_report.txt
├── aes_sha_rsapss_quantum_report.txt
├── sha_aes_mlkem_quantum_report.txt
├── quantum_attack_metrics.csv
└── quantum_attack_metrics.json

Output/IntegratedEducationalQuantumAttack/
├── integrated_quantum_report.txt
├── integrated_quantum_metrics.csv      (aggregates: metric, value, unit, kind, scope)
├── quantum_attack_comparison.csv       (one row per attack)
└── integrated_quantum_metrics.json     (full per-attack detail)
```

CSV column names carry their unit (`_ms`, `_seconds`, `_bytes`, `_bits`), and every numeric column
has a `_kind` companion column with the provenance.

## 12. Source layout

```text
EducationalQuantumAttack/
├── EducationalQuantumAttack.h/.cpp      entry points for one set or all three
├── MessageCrack.h/.cpp                enter a sentence, encrypt it, crack it, report the crack time
├── Common/
│   ├── QuantumAttackTypes.h             Metric, AttackResult, SetAttackReport, configuration
│   ├── QuantumAttackSupport.h/.cpp      formatting, process measurements, backend, budget
│   └── QuantumAttackReport.h/.cpp       text / CSV / JSON output
├── Engine/
│   ├── GroverEngine.h/.cpp              Grover on QuantumSimulator (known and unknown solution count)
│   ├── PhaseEstimationEngine.h/.cpp     iterative phase estimation (engine only; unused by attacks)
│   └── ResourceModel.h/.cpp             logical resource models and scenario time estimates
├── Attacks/
│   ├── ToyAesGroverAttack.h/.cpp        Toy AES: Grover
│   ├── ToyShaQuantumAttack.h/.cpp       Toy SHA: preimage (Grover) and collision (BHT)
│   ├── ToyPublicKeyAnalysis.h/.cpp      Toy ECC / Toy RSA theory only; Toy Module-LWE NOT MODELED
│   └── AttackCommon.h/.cpp
├── Sets/
│   ├── AesShaEcdsaQuantumAttack.h/.cpp
│   ├── AesShaRsaPssQuantumAttack.h/.cpp
│   ├── ShaAesMlKemQuantumAttack.h/.cpp
│   └── SetCommon.h/.cpp
└── Tests/EducationalQuantumAttackTests.cpp

IntegratedEducationalQuantumAttack/
├── IntegratedEducationalQuantumAttack.h/.cpp
├── QuantumAttackComparison.h/.cpp
├── QuantumAttackExport.h/.cpp
└── Tests/IntegratedEducationalQuantumAttackTests.cpp
```

CMake targets: `crypto_educational_quantum_attack` and `crypto_integrated_educational_quantum_attack`.

## 13. Known limitations

- The Shor circuits for Toy ECC and Toy RSA are not implemented; only resource estimates are given.
- Module-LWE has no quantum attack model.
- The cost inside every oracle (AES-GCM verification, SHA-256, table lookup) is not modeled.
- The Shor resource figures are extrapolations of formulas fitted to cryptographic sizes.
- CUDA compilation and GPU execution were not verified for this release; the two new simulator
  operations have no CUDA kernel and always use the CPU path.
- MSVC compilation of the new code was not verified in the development environment.

## 14. References

- L. K. Grover, "A fast quantum mechanical algorithm for database search", STOC 1996.
- M. Boyer, G. Brassard, P. Høyer, A. Tapp, "Tight bounds on quantum searching", Fortschritte der Physik 46, 1998.
- G. Brassard, P. Høyer, A. Tapp, "Quantum cryptanalysis of hash and claw-free functions", LATIN 1998.
- P. W. Shor, "Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer", SIAM J. Comput. 26, 1997.
- S. Beauregard, "Circuit for Shor's algorithm using 2n+3 qubits", Quantum Information and Computation 3, 2003.
- M. Roetteler, M. Naehrig, K. M. Svore, K. Lauter, "Quantum resource estimates for computing elliptic curve discrete logarithms", ASIACRYPT 2017.
- D. J. Bernstein, "Cost analysis of hash collisions: will quantum computers make SHARCS obsolete?", SHARCS 2009.
