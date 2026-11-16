# QFT Benchmarking (2.5)

## What is measured

`QuantumAttackBenchmark` runs the same full-register QFT circuit for each requested qubit count and enabled backend. Each measured repetition creates a fresh simulator, so `setup_ms` captures simulator/backend construction and initial state upload separately from QFT execution.

The reported timings are:

- **setup**: simulator and backend construction, including initial device allocation/upload;
- **qft**: wall-clock duration of `QuantumSimulator::apply_qft`;
- **result_readback**: wall-clock duration of accessing `QuantumSimulator::state`, including CUDA download/synchronization when required;
- **end_to_end**: setup + QFT + result readback;
- **validation**: additional CPU time used to sum state probabilities and check normalization;
- **gpu_kernel**: backend-reported CUDA kernel time;
- **gpu_transfer**: backend-reported host/device transfer time;
- **inter_gpu_transfer**: Multi-GPU shard exchange time;
- **parallel_kernel_wall**: Multi-GPU distributed-kernel wall time;
- **gpu_initialization**: backend-reported device initialization time.

For Multi-GPU, `gpu_kernel` is the sum of kernel time measured across devices. It is not the same quantity as `parallel_kernel_wall`; use the latter when considering elapsed distributed-kernel time. `end_to_end` includes host result readback but excludes the separate validation scan.

Every successful run checks that the QFT output has total probability within `1e-8` of one. This is a normalization sanity check, not a complete numerical equivalence proof against an independent implementation.

## Statistics and comparison

Each backend/qubit-count row reports minimum, median, mean, maximum, and population standard deviation across successful repetitions. `speedup_vs_cpu_single` compares mean QFT wall time against the CPU single-thread baseline for the same qubit count. It is omitted as zero if that baseline did not complete.

`state_amplitudes_per_second` is the number of state-vector amplitudes divided by measured QFT wall time. It is a throughput indicator, not a FLOP/s metric.

Unavailable CUDA backends are emitted as `UNAVAILABLE` rather than being silently replaced by CPU execution. Runtime or allocation errors are reported as `FAILED` or `PARTIAL` rows. A state-vector footprint above the configured limit is emitted as `SKIPPED-MEMORY`.

## Build and run

The standalone benchmark target is built with the rest of the project:

```powershell
cmake -S . -B build -DQUANTUM_ENABLE_CUDA=ON
cmake --build build --config Release
```

Run the default backend sweep:

```powershell
.\build\QuantumAttackBenchmark.exe
```

Choose sizes and repetitions:

```powershell
.\build\QuantumAttackBenchmark.exe --qubits=8,10,12,14,16,18 --repeats=7 --warmup=2 --threads=8
```

Run only CPU backends, or only CUDA backends:

```powershell
.\build\QuantumAttackBenchmark.exe --cpu-only
.\build\QuantumAttackBenchmark.exe --cuda-only --devices=0,1
```

Set a state-vector footprint limit and CSV destination:

```powershell
.\build\QuantumAttackBenchmark.exe --max-memory-mib=512 --csv=Output/qft_benchmark.csv
```

The memory limit applies to the complex state-vector footprint reported by the simulator. It is not a guarantee about total host/device memory use; backend staging buffers, allocator overhead, and temporary working storage may require additional memory.

## Interpretation cautions

- GPU startup, allocation, synchronization, and readback costs can dominate small circuits.
- A GPU result is not automatically faster than CPU. Compare the measured QFT and end-to-end columns on the target machine.
- Run Release builds, close competing GPU workloads, and repeat runs on the same power/thermal conditions for useful comparisons.
- CUDA device availability is detected at runtime. The CPU-only build reports CUDA rows as unavailable.
- The simulator is a classical state-vector program. These measurements do not represent execution on quantum hardware or a practical attack on production cryptography.
