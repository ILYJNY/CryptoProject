# GPU QFT implementation notes

## Backends

Both `CUDAQuantumBackend` and `CUDAMultiGpuQuantumBackend` now expose `apply_qft(target_qubits)`. `QuantumSimulator::apply_qft` routes to the selected CUDA backend when `CudaGpu` or `CudaMultiGpu` is selected. It does not synchronize the state vector to host memory for QFT.

## Decomposition

The simulator's target-qubit list defines the little-endian bit order of the transformed register. The CUDA implementation uses the positive-exponent QFT circuit decomposition:

1. Iterate target positions from the last to the first.
2. Apply Hadamard to the current qubit.
3. Apply controlled-phase gates to each earlier target qubit with angle `pi / 2^(distance)`; the controlled phase multiplies the `|11>` subspace by `exp(i * angle)`.
4. Reverse the target register order using three CNOT gates per pairwise swap.

This matches the positive-sign direct DFT convention used by the CPU backend.

## Single GPU

Hadamard, controlled-phase, and CNOT are CUDA kernels over the persistent state-vector buffers. The QFT method launches these kernels sequentially. The state vector remains resident on the selected device until a host-side state query or other synchronization is requested.

## Multiple GPUs

Hadamard on a distributed qubit uses the existing partner-shard exchange path. Controlled phase is diagonal and uses each shard's global offset, so it requires no inter-GPU exchange. Register reversal uses local or distributed CNOT operations according to the qubit partition. The state remains distributed and device-resident; no full-state gather to CPU memory is part of QFT.

## Performance considerations

This is a gate-decomposed implementation, not a fused QFT kernel. It therefore launches multiple kernels and may be slower than CPU execution for small state vectors. Multi-GPU QFT can incur shard-exchange overhead for Hadamard and swap gates that touch distributed qubits. Benchmark before selecting it for a workload.

## Validation status

The source changes were reviewed structurally only for this delivery. CUDA compilation and runtime behavior must be validated on the target CUDA Toolkit, MSVC toolchain, and GPU topology.


---

## Superseded in revision 2.4

Revision 2.3 used separate Hadamard and controlled-phase kernels and implemented QFT swaps as three CNOT gates. Revision 2.4 replaces these paths with fused QFT stage kernels and direct shard-aware swap operations. See `QFT_GPU_OPTIMIZATION.md` for the current design.
