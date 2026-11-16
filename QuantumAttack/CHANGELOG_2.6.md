# QuantumAttack 2.6

## Integrated algorithm benchmark

- Added `AlgorithmBenchmark` to benchmark the educational Grover search, QFT, and small-input Shor simulator through a shared interface.
- Added CPU single-thread, CPU multi-thread, CUDA single-GPU, and CUDA multi-GPU backend rows. CUDA rows are explicitly marked `UNAVAILABLE` when the backend is not present; they are never substituted with CPU timings.
- Added configurable warm-up and measured repetitions, shot count, CPU thread count, GPU selection, and a state-vector memory ceiling.
- Added mean, median, minimum, maximum, standard deviation, observed Grover target-shot rate / experiment pass rate, operation counts, CPU/GPU timing fields, and CSV export.
- Added the `QuantumAttackAlgorithmBenchmark` command-line executable.
- Extended smoke tests with a small CPU-only integrated benchmark run.

## Scope and interpretation

- Shor remains a tiny educational simulation, with the existing algorithm's input/resource limits. It is not a practical cryptographic attack.
- All timings measure classical state-vector simulation. They are not quantum-hardware timings or evidence that RSA/ECC can be broken in practice.
- CUDA code paths require compilation and execution on a compatible NVIDIA/CUDA environment before their measurements can be trusted.
