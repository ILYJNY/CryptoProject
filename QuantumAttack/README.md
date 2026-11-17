# QuantumAttack

Current revision: **2.8** (2.8 adds a single-qubit phase shift and mid-circuit measurement; see `CHANGELOG_2.8.md`). Revision 2.5 summary: (fused QFT CUDA stages, direct bit-reversal swaps, reusable/pinned transfer staging, and a dedicated backend benchmark runner). Module

QuantumAttack is a drop-in C++20 module for the CryptoProject. It contains the existing state-vector experiments plus selectable CPU and NVIDIA CUDA execution backends.

> This is a classical state-vector simulator. It does not execute on a quantum processor and does not demonstrate a practical break of production cryptography.

## Execution backends

| Backend | Behavior | Notes |
|---|---|---|
| `CpuSingleThread` | Executes state-vector gate loops without worker-pool parallelism | Useful as a baseline |
| `CpuMultiThread` | Uses a reusable worker pool and splits state-vector work into independent ranges | Default backend; `cpu_threads = 0` selects up to 16 workers based on hardware concurrency |
| `CudaGpu` | Keeps the complete state vector in persistent buffers on one NVIDIA GPU | Requires a working CUDA compiler, toolkit, driver, and NVIDIA GPU |
| `CudaMultiGpu` | Splits ONE state vector into contiguous shards distributed over multiple NVIDIA GPUs | Requires 2, 4, 8, ... selected GPUs and sufficient memory on each device |

The single-GPU and multi-GPU CUDA implementations accelerate X, Z, Hadamard, CNOT, controlled phase, phase flip, Grover diffusion, and QFT. In revision 2.4, each QFT stage fuses its Hadamard transform and its controlled-phase rotations into one CUDA kernel. The final bit-reversal swaps use direct permutation kernels and shard-aware exchange paths rather than three CNOT gates. General controlled-permutation operations still synchronize to host memory and execute using the CPU worker pool; these are reported in `cpu_fallback_operations`.

### Multi-GPU state-vector distribution

The global amplitude array is partitioned into equal contiguous shards. With D devices, D must be a power of two and the highest `log2(D)` qubit-index bits identify the owning GPU. Lower-index qubits are local to each GPU; higher-index qubits are distributed across GPUs.

- Local X/H gates and local Z/CNOT operations run independently on every shard.
- Distributed X and Hadamard gates first exchange each shard with its partner shard, then launch one kernel per GPU.
- Distributed Z is a per-shard phase operation.
- CNOT with a distributed target exchanges partner shards and conditionally copies the partner amplitudes based on the global control bit.
- Controlled phase is diagonal: each GPU multiplies amplitudes satisfying both global control masks by the complex phase, without exchanging shards.
- QFT uses fused Hadamard-plus-controlled-phase stage kernels. A stage whose target is distributed exchanges its partner shard before the fused kernel; a local-target stage uses each GPU's local state and global index bits. The final bit-reversal uses local/local swaps, local/distributed partner-shard swaps, or distributed/distributed shard swaps. No full-state host download is required.
- Grover diffusion computes per-GPU partial sums, combines the small reduction results on the host, then updates all shards in parallel.
- Inter-GPU copies use CUDA peer-to-peer when supported. If the topology does not permit peer access, the implementation stages the partner shard through host memory.

All partner copies are completed before any gate kernel writes a shard. This avoids one GPU observing another GPU's already-updated state during a two-way exchange. Host staging arrays are reused across uploads/downloads and host-staged peer copies; CUDA pinned-memory registration is attempted, with pageable-memory copies retained as a fallback. Empty `gpu_devices` selects the largest available power-of-two subset of devices (for example, 3 visible GPUs selects devices 0 and 1). Explicit lists must contain unique valid indices and have a power-of-two length.

## Directory layout

```text
QuantumAttack/
├── Backend/
│   ├── QuantumBackendTypes.h
│   ├── CPU/
│   │   ├── QuantumThreadPool.h/.cpp
│   │   └── CPUQuantumBackend.h/.cpp
│   └── CUDA/
│       ├── CUDAQuantumBackend.h/.cu
│       ├── CUDAQuantumBackendStub.cpp
│       ├── CUDAMultiGpuQuantumBackend.h/.cu
│       └── CUDAMultiGpuQuantumBackendStub.cpp
├── Standard/
│   ├── Core/
│   ├── Algorithms/
│   └── Models/
├── Educational/
│   ├── Experiments/
│   └── Visualization/
├── Reports/
├── Benchmark/
├── Examples/
├── Tests/
├── CMakeLists.txt
└── README.md
```

## Build this folder by itself

Open this folder in CLion, or configure it from a terminal:

```powershell
cmake -S . -B build -DQUANTUM_ENABLE_CUDA=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

To force a CPU-only build:

```powershell
cmake -S . -B build-cpu -DQUANTUM_ENABLE_CUDA=OFF
cmake --build build-cpu --config Release
ctest --test-dir build-cpu -C Release --output-on-failure
```

If CUDA is requested but no CUDA compiler is discovered, CMake uses the CPU implementation and includes a CUDA stub that reports the backend as unavailable. It does not silently label CPU work as GPU work.

## Demo

```powershell
.\build\QuantumAttackDemo.exe --backend=cpu
.\build\QuantumAttackDemo.exe --backend=cpu-multi --threads=8
.\build\QuantumAttackDemo.exe --backend=gpu --device=0
.\build\QuantumAttackDemo.exe --backend=multi-gpu --devices=0,1
```

The demo writes `Output/quantum_backend_report.csv` with backend-specific metrics.


## QFT backend benchmark (2.5)

Build the additional `QuantumAttackBenchmark` executable with the normal project build. It benchmarks QFT across CPU single-thread, CPU multi-thread, and detected CUDA backends. Results include setup, QFT wall time, readback, end-to-end, backend kernel/transfer components, Multi-GPU communication, repeated-run statistics, and speedup versus CPU single-thread. A CSV is written to `Output/qft_benchmark.csv` by default.

```powershell
.\build\QuantumAttackBenchmark.exe
.\build\QuantumAttackBenchmark.exe --qubits=8,10,12,14,16,18 --repeats=7 --warmup=2 --threads=8
.\build\QuantumAttackBenchmark.exe --cpu-only
.\build\QuantumAttackBenchmark.exe --cuda-only --devices=0,1 --csv=Output\qft_gpu.csv
```

See [`Docs/QFT_BENCHMARKING.md`](Docs/QFT_BENCHMARKING.md) for timing definitions, limitations, and interpretation notes. The state-vector memory limit is a limit on the state-vector footprint, not a guarantee of total process/device memory requirements.

## Use it from CryptoProject

Replace the current `add_library(crypto_quantum ...)` source list in the top-level `CryptoProject/CMakeLists.txt` with the source list in `Docs/CMakeIntegration.cmake`. Keep the existing `crypto_common` / `crypto_compute_engine` links and include directories. The new QuantumAttack CUDA backend is independent of the older `ComputeEngine/CUDA/CudaQuantumKernels.cu` implementation.

The existing experiment functions remain source-compatible because their new backend-options parameters have defaults. Select a backend explicitly where needed:

```cpp
#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"

crypto::quantum::QuantumExecutionOptions options;
options.backend = crypto::quantum::QuantumBackendType::CpuMultiThread;
options.cpu_threads = 8;

auto result = crypto::quantum::run_grover_experiment(10, 123, 2048, options);
```

To use one GPU:

```cpp
crypto::quantum::QuantumExecutionOptions options;
options.backend = crypto::quantum::QuantumBackendType::CudaGpu;
options.gpu_device = 0;
```

To distribute one state vector over multiple GPUs:

```cpp
crypto::quantum::QuantumExecutionOptions options;
options.backend = crypto::quantum::QuantumBackendType::CudaMultiGpu;
options.gpu_devices = {0, 1}; // Use {0, 1, 2, 3} for four GPUs.

crypto::quantum::QuantumSimulator simulator(20U, 22U, options);
simulator.apply_hadamard(19U); // Example distributed-qubit gate.
```

If `gpu_devices` is empty, the backend selects the largest available power-of-two device set that can partition the requested register. Multi-GPU mode requires at least two devices and a power-of-two device count. It throws a clear error if the requested devices or state-vector size are unsuitable; it never silently reports CPU work as GPU work.

## Report interpretation

- `elapsed_ms`: end-to-end experiment time, including backend synchronization required by the experiment.
- `cpu_wall_time_ms`: accumulated wall time spent in CPU backend operations.
- `gpu_kernel_time_ms`: accumulated CUDA kernel execution time measured with CUDA events.
- `gpu_transfer_time_ms`: host/device transfer and partial-reduction transfer time.
- `gpu_initialization_time_ms`: CUDA context initialization time (summed across selected devices in multi-GPU mode).
- `gpu_inter_gpu_transfer_time_ms`: time spent moving partner shards between GPUs or through host staging.
- `gpu_parallel_kernel_wall_time_ms`: host wall time around distributed launch and synchronization; unlike summed per-device kernel time, this approximates observed multi-GPU kernel-phase latency.
- `gpu_peer_copy_count` / `gpu_host_staged_copy_count`: number of shard transfers using direct peer access or host staging.
- `cpu_fallback_operations`: operations run by CPU because a GPU kernel is not currently implemented for that operation.

These measurements have different scopes and should not be summed blindly. For small state vectors, GPU launch and transfer overhead may exceed the parallel compute time.

## Current limitations

1. State-vector memory grows exponentially: an n-qubit register stores 2^n complex amplitudes.
2. The standard simulator defaults to a 22-qubit allocation limit; the actual safe limit depends on available RAM/VRAM.
3. CUDA code is included but needs compilation and execution on the user's Windows + MSVC + CUDA environment before it can be considered validated there.
4. CUDA support includes the listed primitive gates and QFT. General controlled permutation still uses CPU multi-thread fallback.
5. Multi-GPU state-vector distribution requires a power-of-two device count. Each GPU stores its complex shard and an additional partner-shard workspace, so device memory use is roughly twice the local share of the state vector, plus reduction buffers. It uses P2P copies where possible and falls back to host-staged shard transfers when peer access is unavailable. Actual transfer performance depends strongly on PCIe/NVLink topology.
6. Multi-GPU QFT remains entirely on the GPU backend through gate decomposition. General controlled permutation still uses CPU multi-thread fallback. QFT involves multiple sequential kernel launches, so launch overhead can dominate small registers; this implementation prioritizes staying device-resident rather than fusing the full transform into one kernel.
7. Shor's algorithm remains a small educational state-vector demonstration, not a practical cryptographic attack.

## Revision 2.4 timing additions

CUDA timing structures and `QuantumBackendStatistics` expose QFT fused-stage counts, QFT swap counts/operations, and whether pinned host staging was enabled. Kernel time, inter-GPU transfer time, general transfer time, and wall time remain separate measurements. These are instrumentation fields; no speedup is claimed without measurements on the target GPU.


## Version 2.6: Integrated algorithm benchmark

The new `QuantumAttackAlgorithmBenchmark` executable benchmarks the educational Grover, QFT, and small-input Shor simulations across CPU single-thread, CPU multi-thread, CUDA single-GPU, and CUDA multi-GPU backends. CUDA rows are reported as `UNAVAILABLE` when CUDA is not built or no suitable device is detected; they are never replaced with CPU measurements.

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --qubits=3,4,5 --repeats=5 --warmup=2 --shots=1024 --threads=8
```

The CSV report defaults to `Output/algorithm_benchmark.csv`. See [Docs/ALGORITHM_BENCHMARKING.md](Docs/ALGORITHM_BENCHMARKING.md) for all options and field meanings.

Shor is restricted to the existing tiny educational simulator and is not a practical attack on real cryptographic systems. All timings are from a classical state-vector simulator, not quantum hardware.

## Benchmark Dashboard (2.7)

After generating `Output/algorithm_benchmark.csv` with `QuantumAttackAlgorithmBenchmark`, create an offline HTML report:

```powershell
py Tools/GenerateBenchmarkReport.py Output/algorithm_benchmark.csv
```

Outputs:
- `Output/algorithm_benchmark_report.html` — offline SVG charts and comparison table
- `Output/algorithm_benchmark_summary.csv` — derived speedup and measurement summary

See `Docs/BENCHMARK_DASHBOARD.md` for options and interpretation notes. The report generator requires only Python 3 standard library modules. All times are classical state-vector simulation measurements, not quantum-hardware measurements.

## Version 2.8: phase shift and mid-circuit measurement

`QuantumSimulator` gained two operations:

- `apply_phase_shift(target, angle)` applies `diag(1, e^{i*angle})` to one qubit.
- `measure_qubit(target, uniform_sample)` measures one qubit in the Z basis in the middle of a
  circuit, collapses the state onto the sampled outcome and renormalizes it. The caller owns the
  random source and passes a uniform sample in `[0, 1)`.

Mid-circuit measurements are counted by `measurement_count()`, separately from `gate_count()`.
Both operations use the CPU reference path. With a CUDA backend selected they synchronize the state
to host memory and are reported in `cpu_fallback_operations`; no CUDA kernel exists for them.
