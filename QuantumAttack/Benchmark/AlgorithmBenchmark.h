#pragma once

#include "../Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto::quantum
{
    enum class BenchmarkAlgorithm
    {
        Grover,
        Qft,
        ShorToy
    };

    struct AlgorithmBenchmarkOptions
    {
        std::vector<std::size_t> qubit_counts{3U, 4U, 5U};
        std::size_t repeats = 3U;
        std::size_t warmup_runs = 1U;
        std::size_t shots = 512U;
        std::size_t cpu_threads = 0U;
        std::size_t max_state_vector_bytes = 64U * 1024U * 1024U;
        bool include_cpu_backends = true;
        bool include_cuda_backends = true;
        int gpu_device = 0;
        std::vector<int> gpu_devices{};
        std::uint32_t shor_number = 15U;
        std::uint32_t shor_base = 2U;
    };

    struct AlgorithmBenchmarkResult
    {
        std::string algorithm;
        std::string backend;
        std::string status;
        std::size_t qubits = 0U;
        std::size_t state_vector_bytes = 0U;
        std::size_t requested_runs = 0U;
        std::size_t successful_runs = 0U;
        std::size_t failed_runs = 0U;
        std::size_t shots = 0U;
        std::size_t cpu_threads = 0U;
        std::size_t cpu_operations = 0U;
        std::size_t gpu_operations = 0U;
        std::size_t cpu_fallback_operations = 0U;
        std::size_t gate_count = 0U;
        std::size_t operation_depth = 0U;
        int gpu_device = -1;
        std::vector<int> gpu_devices{};
        double mean_ms = 0.0;
        double median_ms = 0.0;
        double minimum_ms = 0.0;
        double maximum_ms = 0.0;
        double standard_deviation_ms = 0.0;
        double mean_cpu_wall_ms = 0.0;
        double mean_gpu_kernel_ms = 0.0;
        double mean_gpu_transfer_ms = 0.0;
        double mean_gpu_initialization_ms = 0.0;
        double mean_inter_gpu_transfer_ms = 0.0;
        double mean_parallel_kernel_wall_ms = 0.0;
        double mean_norm_error = 0.0;
        double experiment_pass_rate = 0.0;
        std::string detail;
    };

    [[nodiscard]] std::vector<AlgorithmBenchmarkResult> run_algorithm_benchmark(
        const AlgorithmBenchmarkOptions& options = {});

    [[nodiscard]] std::string format_algorithm_benchmark_result(const AlgorithmBenchmarkResult& result);

    [[nodiscard]] std::string export_algorithm_benchmark_csv(
        const std::vector<AlgorithmBenchmarkResult>& results,
        const std::string& file_path = "Output/algorithm_benchmark.csv");
}
