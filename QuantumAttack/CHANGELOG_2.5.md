# QuantumAttack 2.5

## Added

- Added a standalone `QuantumAttackBenchmark` executable for QFT performance sweeps.
- Added CPU single-thread, CPU multi-thread, single-GPU, and Multi-GPU backend comparison when each backend is available.
- Added configurable qubit lists, repetitions, warm-up runs, CPU thread count, GPU device selection, and state-vector memory-footprint limits.
- Added mean, median, minimum, maximum, and standard deviation for setup, QFT, readback, end-to-end, validation, kernel, transfer, and distributed-kernel timings.
- Added per-size speedup relative to the CPU single-thread baseline and state-amplitudes-per-second throughput indicator.
- Added QFT output normalization sanity checks and explicit `UNAVAILABLE`, `SKIPPED-MEMORY`, `FAILED`, and `PARTIAL` statuses.
- Added a dedicated QFT benchmark CSV report and documentation.

## Notes

- `end_to_end` includes simulator/backend setup, QFT execution, and result readback. Validation scan time is reported separately.
- Multi-GPU aggregate kernel time is distinct from parallel kernel wall time and inter-GPU communication time.
- CUDA compilation and physical GPU benchmarks must be performed on a machine with a compatible CUDA toolkit, driver, and NVIDIA hardware.
