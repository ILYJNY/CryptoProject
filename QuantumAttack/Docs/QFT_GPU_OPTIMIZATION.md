# QFT GPU Optimization (2.4)

## Fused stage

For target position `j` in the QFT circuit, the implementation now combines the Hadamard transform on `target_qubits[j]` and all controlled-phase operations controlled by `target_qubits[0..j-1]` into one kernel. For each paired amplitude, the kernel computes the two Hadamard outputs and accumulates the applicable phase rotations for the high branch. The phase rotations are diagonal and commute with one another, so combining their phase angles preserves the stage result.

This reduces the number of QFT stage launches from one Hadamard plus `j` controlled-phase launches to one fused launch for each `j`. Each amplitude pair still performs work proportional to the number of controls in that stage.

## Direct bit-reversal swaps

The final bit-reversal permutation uses one direct swap kernel for each pair of reversed target positions instead of three CNOT kernels. Multi-GPU swaps are partition-aware:

- local/local: swap within each shard;
- local/distributed: exchange the needed partner shard and select the transposed local index;
- distributed/distributed: exchange the complete partner shards.

## Transfer staging

The single-GPU and Multi-GPU backends reuse host-side real/imaginary staging arrays. They attempt to register those arrays as CUDA pinned memory and use asynchronous copy calls followed by synchronization. If host registration fails, the code falls back to ordinary pageable-memory copies. Multi-GPU host-staged peer exchange also reuses these arrays rather than allocating a new temporary vector for every exchange.

## Metrics

`CudaQuantumTiming` and `CudaMultiGpuTiming` expose fused QFT stage counts and QFT swap counts. They also report whether pinned host staging was successfully enabled. `QuantumBackendStatistics` aggregates the QFT counts and pinned-memory usage so callers can inspect them through `QuantumSimulator::backend_statistics()`. The existing kernel, transfer, inter-GPU transfer, and wall-time counters remain separate.

## Limits and validation

Kernel fusion reduces launch count but does not guarantee a runtime speedup on every GPU or state size. The CUDA code has not been compiled or run as part of this archive. Numerical validation against the CPU implementation and hardware-specific performance measurements are still required.
