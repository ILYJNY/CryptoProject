# Common Module

The Common module contains utilities shared by CryptoSystem, CryptoAnalyzer,
and IntegratedMode.

## ErrorHandling

`CryptoException` is the common exception type. It stores an `ErrorCode` and
an English diagnostic message. Use `raise_error()` for expected project errors.

## BigInteger

`BigInt` aliases `boost::multiprecision::cpp_int`. The module currently provides
bit length, greatest common divisor, normalized modulo, modular exponentiation,
and decimal/hexadecimal conversion.

## Random

`SecureRandom` reads random bytes from the operating system's cryptographic
random source. It provides byte generation, uniformly distributed 64-bit
integers, and uniformly distributed non-negative `BigInt` values below an
exclusive upper bound. Do not replace this source with `std::rand`,
`std::mt19937`, or a simulation PRNG for cryptographic key material.

## Encoding

The encoding module provides hexadecimal encoding/decoding and strict UTF-8
validation/conversion. It does not normalize Unicode text; normalization, if
needed by a protocol, must be specified at that protocol layer.

## Serialization

`ByteWriter` and `ByteReader` encode unsigned integers in little-endian order.
Strings and byte arrays use a 64-bit length prefix. Readers enforce configurable
maximum lengths and reject truncated input. This is a project-local binary
format, not a claim of compatibility with an external standard.

## Logger

`Logger::instance()` returns the process-wide logger. Console logging is enabled
by default, and the default minimum severity is `INFO`. A log file can be
configured with `set_file()`.

## PerformanceMonitor

`ScopedTimer` records elapsed wall time with `std::chrono::steady_clock` and
process CPU time with `std::clock`. The latter is process-wide CPU time, not
per-thread CPU time. The monitor groups repeated stage/backend runs and exports
detailed and summary CSV files. CUDA event measurements will be produced by the
CUDA compute module and passed to `record_gpu_timing()`.

Example:

```cpp
crypto::PerformanceMonitor monitor;

const auto result = monitor.measure("RSA.KeyGeneration", "CPU", [&]() {
    return perform_educational_key_generation();
});

monitor.export_csv("Output/performance.csv");
monitor.export_summary_csv("Output/performance-summary.csv");
```
