# QuantumAttack 2.8

## Added

- `QuantumSimulator::apply_phase_shift(target, angle)` — the single-qubit phase gate
  `diag(1, e^{i*angle})`.
- `QuantumSimulator::measure_qubit(target, uniform_sample)` — a mid-circuit projective Z-basis
  measurement of one qubit. The caller supplies a uniform sample in `[0, 1)`; the state collapses
  onto the sampled outcome and is renormalized. Returns the outcome and its probability.
- `QuantumSimulator::measurement_count()` — mid-circuit measurements are counted separately from
  gates; they still advance the operation-depth counter.
- CPU backend functions `apply_phase_shift`, `probability_of_one` and `collapse_qubit`, parallelized
  with the existing worker pool.

## Behavior

- Existing operations, counters and results are unchanged.
- Both new operations always run on the CPU reference path. When a CUDA backend is selected the
  state is synchronized to host memory first and the operation is counted in
  `cpu_fallback_operations`, exactly like `apply_controlled_permutation`. They are never counted as
  GPU operations.

## Verification status

- CPU single-thread and multi-thread paths give identical states (covered by
  `QuantumAttackSmokeTests` and `QuantumSmokeTests`).
- No CUDA kernel was added. CUDA compilation and GPU execution were not verified for this release.
