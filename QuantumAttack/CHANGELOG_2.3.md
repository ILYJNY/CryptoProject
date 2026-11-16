# QuantumAttack 2.3

## Added
- GPU QFT support for single-GPU CUDA execution.
- GPU QFT support for multi-GPU state-vector execution.
- CUDA controlled-phase gate for both CUDA backends.
- QFT routing in `QuantumSimulator::apply_qft` now follows the selected CUDA backend instead of CPU fallback.
- QFT implementation notes and updated backend documentation.

## Implementation
- QFT is implemented as a positive-phase gate decomposition: Hadamard, controlled phase, and register reversal via three CNOT gates per swap.
- Multi-GPU controlled phase uses each shard's global offset and does not require shard exchange.
- Multi-GPU Hadamard and CNOT reuse the existing shard-exchange paths when acting on distributed qubits.

## Remaining limitation
- General controlled permutation still uses CPU multi-thread fallback.
- This release's new CUDA QFT code has not been compiled or run on a CUDA device in the packaging environment. Validate with the target CUDA Toolkit, MSVC toolset, and GPU topology.
