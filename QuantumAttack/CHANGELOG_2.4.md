# QuantumAttack 2.4

## QFT kernel fusion and transfer staging

- Replaced separate Hadamard and per-control Controlled Phase launches in each QFT stage with one fused CUDA stage kernel.
- Replaced three-CNOT QFT bit-reversal swaps with direct one-pass swap kernels on single-GPU and Multi-GPU backends.
- Multi-GPU fused QFT stages now handle both local and distributed target qubits. Distributed Hadamard stages exchange the partner shard once, then apply all phase factors in the same local kernel.
- Added local/local, local/distributed, and distributed/distributed shard-aware swap paths.
- Reused host staging arrays for state uploads/downloads and host-staged peer copies. Host buffers are registered as pinned memory when supported; pageable-memory copies remain the fallback.
- Added timing counters for fused QFT stages, swap operations, and pinned-memory availability.

## Verification status

CUDA compilation, GPU execution, multi-GPU topology behavior, and numerical comparison against the CPU reference have not been verified in this release. The changes are intended as an implementation update, not a measured performance claim.
