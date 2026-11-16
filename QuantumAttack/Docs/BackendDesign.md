# QuantumAttack Backend Design Notes

## CPU work partitioning

The state vector contains N = 2^n complex amplitudes. The CPU backend parallelizes independent state-vector regions:

- X and Hadamard: N/2 disjoint amplitude pairs.
- Z: N amplitudes.
- CNOT: disjoint pairs selected by the control and target masks.
- Phase flip: one marked basis index (constant work; no useful parallel split).
- Diffusion: parallel partial reductions followed by parallel amplitude updates.
- QFT: independent target-register blocks; each block performs the direct DFT used by the educational CPU simulator.
- Controlled permutation: independent control-on blocks, reading from an immutable snapshot so non-involutive permutations are also handled correctly.

The `QuantumThreadPool` starts workers lazily when an operation is large enough to split. This avoids paying thread startup cost for one- or two-qubit educational demonstrations.

## CUDA state lifecycle

`CUDAQuantumBackend` owns a persistent pair of device arrays (real and imaginary parts). The lifecycle is:

1. Upload once when GPU mode is selected or host state changes.
2. Run supported gate kernels against the resident device arrays.
3. Download only when CPU fallback or a host-side state query requires it.

The simulator tracks whether the host or device copy is current. If an operation does not yet have a CUDA implementation, it downloads the latest GPU state, executes on the CPU worker pool, and marks the GPU copy stale. The next GPU gate performs a fresh upload. QFT no longer takes this fallback: it is decomposed into GPU Hadamard, controlled-phase, and swap operations.

## Numerical and execution notes

- State-vector gates operate on complex double precision values.
- CUDA uses split real/imaginary double arrays to keep device-side layout explicit.
- GPU reduction for diffusion computes block partial sums on the GPU, transfers the small partial-sum arrays, computes the final mean, then applies the diffusion update on the GPU.
- CUDA events measure kernel time. Host/device transfer timings use synchronized wall-clock measurements.
- Floating-point summation order differs between serial, threaded, and GPU reductions. Tests compare states with a numerical tolerance rather than byte-for-byte equality.

## Explicit limitations

This is a classical simulation of quantum state evolution. A GPU kernel operating on 2^n amplitudes does not make it a quantum computer. The current CUDA backend supports one selected NVIDIA device; it does not distribute one state vector across multiple GPUs.


## Multi-GPU state-vector partitioning

The `CudaMultiGpu` backend partitions one global state vector across D devices. D must be a power of two. Every device stores `2^n / D` consecutive amplitudes, and the high `log2(D)` state-index bits select the device rank. This makes the remaining low-order qubits local to each device.

For a gate on a distributed qubit, each shard is paired with the shard whose rank differs by that distributed bit. The backend copies all partner shards into per-device remote buffers before launching any writer kernel. This ordering is essential for two-way gates: no source shard may be overwritten before every peer has captured its original amplitudes.

The CUDA backend uses `cudaMemcpyPeer` when directed peer access is available. If it is not available, it copies the partner chunk device-to-host and then host-to-device. Both routes are synchronous in this implementation and are included in inter-GPU transfer timing. The host-staging route is intended as a correctness fallback but can be substantially slower. The inter-GPU transfer metric is a subset of total GPU transfer time, not an additional time to add to it.

Gate mapping:

- X on a local qubit: local pair swap on each device.
- X on a distributed qubit: replace each shard with its partner shard.
- Z on a local qubit: local sign change; Z on a distributed qubit: negate all amplitudes on ranks whose corresponding device bit is one.
- Hadamard on a local qubit: local pair transform; Hadamard on a distributed qubit: use each shard and its partner to compute the low/high output branch.
- CNOT with local target: local pair swap conditioned on the global control bit; CNOT with distributed target: exchange partner shards and conditionally copy remote amplitudes.
- Phase flip: update the unique shard containing the marked basis index.
- Diffusion: compute partial complex sums independently on each GPU, reduce the small partial arrays on the host, and launch the reflection update on all devices.

General controlled permutation still uses CPU fallback. Before fallback, all shards are downloaded into the global host state; after the CPU operation, the next multi-GPU operation uploads the new state. QFT does not use this fallback; it remains GPU-resident through Hadamard, controlled-phase, and CNOT kernels.

Metrics distinguish the sum of kernel time across devices from the wall-clock duration of a parallel launch/synchronization phase. Inter-GPU transfer time, peer-copy count, and host-staged-copy count are reported separately. These values must not be conflated: a sum of per-device kernel times may exceed wall-clock latency when devices execute concurrently.
