# ComputeEngine

The ComputeEngine provides a CPU fallback and an optional CUDA backend.

## Available C++ API paths

- CUDA device discovery and device-property reporting.
- `vector_add_u32`: CPU, AUTO, selected GPU, and MULTI-GPU execution.
- Multi-GPU workload splitting weighted by reported multiprocessor count. GPU outputs are not
  cross-validated against one another.
- `sha256_short_batch`: CPU or CUDA SHA-256 hashing for messages no longer than 55 bytes, which
  fit one padded SHA-256 block. Longer messages are rejected by this batch API.
- CUDA state-vector methods for Hadamard, phase flip, and diffusion are exposed in
  `QuantumSimulator`; ordinary algorithm helper functions still use the CPU gate methods.
- Wall-clock, process CPU, GPU kernel, host/device transfer, and initialization timing fields.

The main menu's Compute Engine entry currently displays device information and build availability;
it does not launch an interactive workload or offer a backend-selection prompt. C++ callers can
construct `ComputeOptions` to select `AUTO`, `CPU`, `GPU`, or `MULTI-GPU`.

## Backend behavior

- `AUTO`: use a GPU for workloads at or above `minimum_gpu_work_items`; otherwise use CPU.
- `CPU`: always use CPU.
- `GPU`: use `selected_gpu_index`, or the first GPU if the index is negative.
- `MULTI-GPU`: distribute supported workload chunks across detected CUDA devices. If only one GPU
  exists, that device is used; if none exists, CPU fallback is selected.

## Timing notes

- `wall_time_ms` includes discovery, scheduling, transfers, and computation.
- `gpu_kernel_time_ms` is the sum of device kernel times in multi-GPU mode, not aggregate elapsed
  wall time.
- `gpu_transfer_time_ms` includes host-to-device and device-to-host CUDA events.
- `gpu_initialization_time_ms` estimates device selection and first context setup.
- `process_cpu_time_ms` uses `std::clock()` and is process-wide, not per-thread CPU time.

CUDA code is compiled only when CMake detects a compatible CUDA compiler and toolkit. CUDA source
was not compiled or executed on the target Windows/GPU environment in this delivery.
