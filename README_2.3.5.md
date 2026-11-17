# CryptoProject 2.3.5 — Independent & Integrated Educational Quantum Attack Analysis

2.3.5 adds two modules on top of 2.3.4. Nothing from 2.3.4 was removed.

| New module | What it does |
|---|---|
| `EducationalQuantumAttack/` | Analyzes each of the three educational cryptosystem sets **independently** against quantum attacks, on the set's real toy parameters. |
| `IntegratedEducationalQuantumAttack/` | Runs the three independent analyses and **compares** their results. It does not merge the cryptosystems. |

The existing `QuantumAttack/` library is the engine (a classical state-vector simulator). The new
modules are the analysis system built on it. The classical analyses
(`EducationalCryptoSetAnalysis/`, `IntegratedEducationalCryptoAnalysis/`) are unchanged and separate.

> **Security notice.** Educational project with deliberately tiny parameters. Nothing here breaks
> AES-128, SHA-256, P-256, RSA-2048 or ML-KEM-768, and no reported figure is a time to break a real
> cryptosystem.

## 한국어 요약

- **새 모듈 2개**: `EducationalQuantumAttack/`(세 교육용 암호 시스템을 각각 독립적으로 양자 공격 분석)와
  `IntegratedEducationalQuantumAttack/`(세 분석 결과를 모아 비교). 기존 고전 분석 모듈과 별개입니다.
- **실제로 시뮬레이터에서 실행되는 공격 회로**
  - Toy AES(12비트 키 공간): Grover — 실제 생성된 암호문을 대상으로 키를 복구하고 AES-GCM으로 검증
  - Toy SHA 역상(16비트): Grover — 세트 메시지의 실제 다이제스트를 대상으로 탐색
  - Toy SHA 충돌: BHT(Brassard–Høyer–Tapp) — Grover 단독으로 표시하지 않으며 역상 결과와 분리
- **회로가 구현되지 않은 항목(명시적 미구현 처리)**
  - Toy ECC: Shor(ECDLP)에 대응시키되 **회로 미구현**, 공식 기반 자원 추정만 제공
  - Toy RSA: Shor(소인수분해)에 대응시키되 실제 24비트 모듈러스용 **회로 미구현**, 자원 추정만 제공.
    기존 `N=15` 실험은 "별도의 알고리즘 검증 실험"으로만 표시되며 실제 모듈러스 공격으로 취급하지 않음
  - Toy Module-LWE: **NOT MODELED** — Shor를 적용하지 않고, 큐비트·게이트·시간 수치를 만들지 않음
  - 따라서 각 세트의 상태는 항상 `PARTIAL`이며 "전부 성공"으로 표시되지 않습니다.
- **세 가지 시간을 분리**: A 양자 시뮬레이터 실행 시간(측정) / B 추정 양자 공격 시간(가정 기반 추정) /
  C 고전 공격 실행 시간(측정). 서로 더하지 않습니다.
- **값이 없는 항목은 0이 아니라** `NOT MODELED`, `NOT EXECUTED`, `N/A`, `UNKNOWN`으로 출력합니다.
- **메뉴**: 기존 1–8번은 그대로, `9. Educational Quantum Attack`, `10. Integrated Educational Quantum Attack`,
  `11. Quantum Simulator Benchmark` 추가.
- **검증**: CPU 전용 Linux에서 GCC 13(Release/Debug), Clang 18(Release) 빌드 및 CTest 9/9 통과.
  **MSVC 빌드와 CUDA 빌드·GPU 실행은 검증하지 못했습니다.**

## 1. What is implemented and what is not

| Component | Problem | Algorithm | Status |
|---|---|---|---|
| Toy AES — AES-128-GCM, 12 unknown key bits | unstructured key search | Grover | circuit **simulated**; key recovered and verified |
| Toy SHA preimage — SHA-256 truncated to 16 bits | preimage search | Grover (unknown number of solutions) | circuit **simulated**; preimage found and verified |
| Toy SHA collision | collision search | Brassard–Høyer–Tapp | circuit **simulated**; collision found and verified |
| Toy ECC — curve over F_97, base point of order 50 | elliptic-curve discrete logarithm | Shor (ECDLP) | **theory only**; circuit NOT IMPLEMENTED |
| Toy RSA — 24-bit modulus | integer factoring | Shor (order finding) | **theory only**; circuit for this modulus NOT IMPLEMENTED |
| Toy Module-LWE — n = 4, k = 2, q = 257 | Module-LWE | none; Shor does not apply | **NOT MODELED** |

Please read the last three rows carefully:

- This release recovers **no** ECC private scalar and **no** RSA factor with a quantum method. Those
  two reports show the real parameters, the corresponding algorithm, `Circuit implemented: NO`,
  `Attack outcome: NOT ATTEMPTED`, and resource estimates from published formulas.
- The existing toy Shor experiment on `N = 15` is run inside the Toy RSA report as a *separate
  algorithm-validation experiment*. Its success is not an attack on the generated modulus and does
  not change the RSA outcome.
- Module-LWE gets no quantum figure of any kind.
- Because of this, every set reports `PARTIAL`, and so does the integrated analysis.

## 2. Menu

```text
1. CryptoSetAnalysis (three independent sets)                       unchanged
2. IntegratedCryptoAnalysis (all three sets together)               unchanged
3. Primitive diagnostics / educational examples                     unchanged
4. CryptoAnalyzer                                                   unchanged
5. QuantumAttack Simulator                                          unchanged
6. Educational Integrated Analysis (toy instances)                  unchanged
7. Benchmark                                                        unchanged
8. Compute Engine                                                   unchanged
9. Educational Quantum Attack (three independent toy sets)          NEW
10. Integrated Educational Quantum Attack (compare the three sets)  NEW
11. Quantum Simulator Benchmark (QuantumAttack engine)              NEW
0. Exit
```

- **9** asks which set to analyze (or all three, independently), a message, and the simulator
  backend. It prints the full report and writes the files listed in section 4.
- **10** runs all three analyses, prints the integrated comparison and writes its files.
- **11** runs the existing `QuantumAttack` algorithm benchmark (Grover, QFT, toy Shor) on every
  backend. It measures the simulator, not an attack.

The classical educational analyses stay where they were: `3` → `2. Educational Mode` → `6` / `7`.

## 3. Reading a report

Each attack report has four numbered sections.

1. **Circuit executed on the state-vector simulator** — measured values for the circuit that really ran.
2. **Logical resource model** — computed or estimated; never executed.
3. **Time** — three different quantities that are never added together:
   - **A. Quantum simulator runtime**: how long this classical computer needed to simulate the circuit.
   - **B. Estimated quantum attack time**: a scenario estimate for hypothetical quantum hardware, with its basis.
   - **C. Classical attack runtime**: the existing classical attack on the same instance, measured.
4. **Computer resources of the classical simulation** — backend, threads, memory, GPU.

Every number is tagged `[measured]`, `[computed]` or `[estimated]`. A value that does not exist is
printed as `NOT MODELED`, `NOT EXECUTED`, `N/A` or `UNKNOWN`. These never mean zero.

All qubit counts are logical qubits. Error-correction overhead and physical qubits are excluded.

Example (Toy AES, abbreviated):

```text
[Toy AES] Grover  |  SIMULATED  |  SUCCEEDED
Attack target           : Toy AES: AES-128-GCM with 12 unknown key bits
Recovered values        :
    AES-128 key: 00000000000000000000000000000E32
    Decrypted plaintext: Hello
[1] CIRCUIT EXECUTED ON THE STATE-VECTOR SIMULATOR
  Total qubits     : 12 [measured]
  Oracle calls     : 50 [measured]
[2] LOGICAL RESOURCE MODEL (computed or estimated; never executed)
  Total qubits     : 21 [computed] (lower bound; excludes oracle workspace)
  Gates by type    : H = 1312; X = 1200; Toffoli = 950
[3] TIME - three different quantities; they are never added together
  A. Quantum simulator runtime ...   simulation : 0.913 ms [measured]
  B. Estimated quantum attack time . estimate   : 50.000 microseconds [estimated]
  C. Classical attack runtime ...... runtime    : 34.082 ms [measured]
```

## 4. Output files

```text
Output/EducationalQuantumAttack/
├── aes_sha_ecdsa_quantum_report.txt
├── aes_sha_rsapss_quantum_report.txt
├── sha_aes_mlkem_quantum_report.txt
├── quantum_attack_metrics.csv
└── quantum_attack_metrics.json

Output/IntegratedEducationalQuantumAttack/
├── integrated_quantum_report.txt
├── integrated_quantum_metrics.csv
├── quantum_attack_comparison.csv
└── integrated_quantum_metrics.json
```

The directories follow the project's existing `Output/<Module>/` convention. CSV column names carry
their unit (`_ms`, `_seconds`, `_bytes`, `_bits`); each numeric column has a `_kind` column with its
provenance. Missing values are written as text in CSV and as `null` in JSON.

## 5. Using the modules from C++

```cpp
#include "EducationalQuantumAttack/EducationalQuantumAttack.h"
#include "IntegratedEducationalQuantumAttack/IntegratedEducationalQuantumAttack.h"
#include "IntegratedEducationalQuantumAttack/QuantumAttackExport.h"

using namespace crypto::educational_quantum_attack;

QuantumAttackConfig config;                      // CPU multi-thread by default
config.seed = 12345;                             // 0 = fresh seed from the OS

// One set, on an instance generated with the real educational parameters.
const AesShaRsaPssTarget target = generate_aes_sha_rsapss_target("Hello");
const SetAttackReport report = run_aes_sha_rsapss_quantum_attack(target, config);
std::cout << format_set_report(report);

// All three sets, each analyzed independently.
const std::vector<SetAttackReport> reports = run_all_quantum_attacks("Hello", config);
ExportedFiles files;
(void)export_quantum_attack_reports(reports, "Output/EducationalQuantumAttack", files);

// Integrated comparison.
namespace integrated = crypto::integrated_educational_quantum_attack;
const integrated::IntegratedResult result = integrated::run("Hello", config);
std::cout << result.report;
```

A set analysis works on exactly the instance it is given. The component attacks receive only the
public instance; the withheld ground truth is used afterwards to check a recovered value.

Configuration (`QuantumAttackConfig`):

| Field | Meaning |
|---|---|
| `execution` | simulator backend (`CpuMultiThread`, `CpuSingleThread`, `CudaGpu`, `CudaMultiGpu`) |
| `budget` | maximum qubits (26) and working memory (2 GiB) a simulation may use; larger circuits are reported as theory only |
| `scenario` | assumed seconds per Grover iteration and per Toffoli gate for time B |
| `seed` | measurement seed; `0` draws a fresh one |
| `max_quantum_attempts` | re-runs of a circuit whose measured result does not verify |
| `run_classical_baselines`, `run_validation_experiments`, `include_reference_scenarios` | optional report parts |
| `progress` | optional callback for progress lines |

CMake targets: `crypto_educational_quantum_attack`, `crypto_integrated_educational_quantum_attack`.

## 6. Build and test

The build is unchanged from 2.3.4. CPU-only example:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCRYPTO_ENABLE_CUDA=OFF
```

```bash
cmake --build build
```

```bash
ctest --test-dir build --output-on-failure
```

On Windows use the existing CLion presets (`msvc-ninja-debug`, `msvc-ninja-release`,
`cpu-only-debug`) exactly as before. With `CRYPTO_ENABLE_CUDA=ON` (the default) CMake falls back to
the CPU when no CUDA compiler is found.

Nine CTest targets are registered: the seven from 2.3.4 plus `EducationalQuantumAttackTests` and
`IntegratedEducationalQuantumAttackTests`. In a Debug build the two new targets take noticeably
longer (tens of seconds) because the state-vector simulation is not optimized.

### What was verified, and what was not

| Configuration | Result |
|---|---|
| GCC 13.3, Release, Linux, no CUDA compiler present (CPU) | build OK, no warnings from project sources, CTest 9/9 passed |
| GCC 13.3, Debug, `CRYPTO_ENABLE_CUDA=OFF` | build OK, CTest 9/9 passed |
| Clang 18.1, Release, `CRYPTO_ENABLE_CUDA=OFF` | build OK, CTest 9/9 passed (warnings only in pre-existing files) |
| Standalone `QuantumAttack/` build | `QuantumAttackSmokeTests` passed |
| Windows / MSVC | **not verified** |
| CUDA compilation and GPU execution | **not verified** (no CUDA toolkit or GPU was available) |

## 7. CUDA

- The Grover-type circuits use simulator operations that have CUDA kernels (Hadamard, phase flip,
  diffusion), so they can run on a CUDA backend when one is available.
- If a CUDA backend is requested but unavailable, the circuits run on the CPU and the report says
  `UNAVAILABLE ... executed on CPU-MULTI`. A CPU run is never labeled as a GPU run, and GPU kernel
  and transfer times are shown only when GPU kernels really ran.
- The two simulator operations added in `QuantumAttack` 2.8 have no CUDA kernel and always use the
  CPU path.
- None of the CUDA paths were compiled or run for this release.

## 8. Further reading

- `QUANTUM_ATTACK_DESIGN.md` — design, attack models, resource models, assumptions, limitations, references.
- `CHANGELOG_2.3.5.md` — complete list of changes and the validation record.
- `QuantumAttack/CHANGELOG_2.8.md` — simulator additions.
- `README.md` — the project as a whole.
