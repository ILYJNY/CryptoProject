# Integrated Algorithm Benchmark

Version 2.6 adds one benchmark entry point for the educational Grover, QFT, and small-input Shor experiments.

## Build

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

CUDA is detected by CMake when `QUANTUM_ENABLE_CUDA=ON`. If CUDA is unavailable, CPU backends remain buildable and CUDA benchmark rows are reported as `UNAVAILABLE`.

## Run

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe
```

Example:

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --qubits=3,4,5 --repeats=5 --warmup=2 --shots=1024 --threads=8 --shor-number=15 --shor-base=2
```

CPU only:

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --cpu-only
```

CUDA only:

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --cuda-only --devices=0,1
```

Custom CSV path:

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --csv=Output\algorithm_benchmark.csv
```

## Output

The CSV contains one row per algorithm, qubit size, and backend. It records status, run counts, timing summaries, success ratio, state-vector size, operation counts, CPU/GPU timing counters, selected GPU devices, and a concise experiment detail string.

`UNAVAILABLE` means the requested backend could not be used. `SKIPPED-MEMORY` means the estimated state vector exceeds `--max-memory-mib`. `SKIPPED-ALGORITHM-LIMIT` means the requested size exceeds the educational algorithm's documented limit. These rows are not measured samples.

## Interpretation

- Grover and QFT use the existing educational algorithm implementations.
- Shor is the existing tiny-input toy simulation, not a practical cryptographic attack.
- All measurements are classical state-vector simulation timings, not timings from quantum hardware.
- GPU kernel, transfer, and initialization counters are backend-reported values. A zero value can mean that the backend does not expose that counter or that the operation did not use it; it must not be interpreted as proof of zero hardware overhead.
- CUDA builds and runs must be verified on the target machine before using GPU performance numbers.
