# CryptoProject 2.3.1

## Added
- Educational crypto-set reports now compare the same SHA-256 batch across single-thread CPU, multi-thread CPU, and CUDA GPU execution.
- Reports include wall-clock runtime, throughput, CPU thread count, GPU kernel/transfer timings, GPU availability, and output-equivalence verification.
- Educational set CSV and integrated educational CSV exports include the backend benchmark measurements.

## Notes
- GPU results are marked unavailable when CUDA was not compiled or no CUDA-capable device is detected; the program does not substitute CPU timings as GPU results.
- The SHA-256 batch is a compute-throughput benchmark and is not a cryptographic attack-time estimate.
