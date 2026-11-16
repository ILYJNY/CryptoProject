# QuantumAttack 2.7 — Benchmark Dashboard

Version 2.7 adds an offline report generator for the CSV produced by `QuantumAttackAlgorithmBenchmark`. It uses only the Python 3 standard library; no pandas, matplotlib, browser connection, or third-party package is required.

## 1. Run a benchmark

From the `QuantumAttack` project directory:

```powershell
.\build\QuantumAttackAlgorithmBenchmark.exe --qubits=3,4,5,6 --repeats=5 --warmup=2 --shots=1024 --threads=8 --csv=Output/algorithm_benchmark.csv
```

Use small qubit counts first. State-vector memory grows exponentially with qubit count (`2^n` complex amplitudes); do not increase the range without checking available memory.

## 2. Generate the report

```powershell
py Tools/GenerateBenchmarkReport.py Output/algorithm_benchmark.csv
```

Optional output paths:

```powershell
py Tools/GenerateBenchmarkReport.py Output/algorithm_benchmark.csv --html=Output/report.html --summary-csv=Output/summary.csv
```

The generated HTML contains offline SVG charts for:
- execution time by qubit count and backend (logarithmic Y-axis)
- state-vector memory by qubit count
- speedup against a matching `CPU-SINGLE` row
- Multi-GPU efficiency when device information is present
- a data table with algorithm, backend, status, mean time, speedup, and experiment pass rate

A derived summary CSV includes kernel, transfer, inter-GPU transfer, pass-rate, and speedup fields.

## 3. Interpretation cautions

- These are classical state-vector simulator measurements, not quantum-hardware timings.
- A missing CPU baseline means speedup is reported as zero/undefined in the derived summary rather than fabricated.
- Multi-GPU efficiency is a rough descriptive ratio (speedup divided by the number of listed devices), not a controlled strong-scaling result.
- `UNAVAILABLE` and `SKIPPED` backends remain visible in the source CSV and are not silently converted into CPU measurements.
- Compare only runs made with the same build configuration, machine, qubit count, shots, and repeat settings.
