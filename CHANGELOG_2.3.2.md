# CryptoProject 2.3.2

## Corrected Educational Toy SHA analysis
- Integrated Toy SHA-256 truncated collision search into all three educational cryptosystem set analyses.
- Preserved the real SHA-256 calculation while truncating the visible digest to 16 bits.
- Replaced the unrelated 32,768-message standard SHA-256 throughput benchmark with actual collision-search workloads.
- Added single-thread CPU, multi-thread CPU, and CUDA GPU execution paths. GPU results are reported as UNAVAILABLE unless the CUDA backend actually executes.
- Added collision inputs, truncated digest, attempts, elapsed times, and verification status to text and CSV reports.
- Integrated educational analysis continues to run three independent sets; it does not combine them into a hybrid cryptosystem.

## Validation
- CMake Release build: passed with GNU C++ 14.2, C++20, CUDA disabled.
- CTest: 7/7 passed.
- CUDA GPU execution and Windows MSVC/CUDA 13.5 were not validated in this environment.
