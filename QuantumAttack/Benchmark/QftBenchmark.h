#pragma once

#include "../Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <string>
#include <vector>

namespace crypto::quantum
{
    struct BenchmarkTimingSummary
    {
        double minimum_ms = 0.0;
        double median_ms = 0.0;
        double mean_ms = 0.0;
        double maximum_ms = 0.0;
        double standard_deviation_ms = 0.0;
    };

    struct QftBenchmarkOptions
    {
        std::vector<std::size_t> qubit_counts{8U, 10U, 12U, 14U, 16U};
        std::size_t repeats = 5U;
        std::size_t warmup_runs = 1U;
        std::size_t max_state_vector_bytes = 256U * 1024U * 1024U;
        std::size_t cpu_threads = 0U;
        bool include_cpu_backends = true;
        bool include_cuda_backends = true;
        int gpu_device = 0;
        std::vector<int> gpu_devices{};
    };

    struct QftBenchmarkResult
    {
        std::size_t qubits = 0U;
        std::size_t state_vector_bytes = 0U;
        std::string backend;
        std::string status;
        std::size_t requested_runs = 0U;
        std::size_t successful_runs = 0U;
        std::size_t failed_runs = 0U;
        std::size_t gate_count = 0U;
        std::size_t operation_depth = 0U;
        std::size_t cpu_threads_used = 0U;
        int gpu_device_used = -1;
        std::vector<int> gpu_devices_used{};
        BenchmarkTimingSummary setup;
        BenchmarkTimingSummary qft;
        BenchmarkTimingSummary result_readback;
        BenchmarkTimingSummary end_to_end;
        BenchmarkTimingSummary validation;
        BenchmarkTimingSummary cpu_wall;
        BenchmarkTimingSummary gpu_kernel;
        BenchmarkTimingSummary gpu_transfer;
        BenchmarkTimingSummary gpu_initialization;
        BenchmarkTimingSummary inter_gpu_transfer;
        BenchmarkTimingSummary parallel_kernel_wall;
        double state_amplitudes_per_second = 0.0;
        double speedup_vs_cpu_single = 0.0;
        double maximum_norm_error = 0.0;
        double mean_gpu_peer_copies = 0.0;
        double mean_gpu_host_staged_copies = 0.0;
        double mean_gpu_qft_fused_stages = 0.0;
        double mean_gpu_qft_swaps = 0.0;
        bool pinned_host_memory_used = false;
        std::string error_message;
    };

    [[nodiscard]] std::vector<QftBenchmarkResult> run_qft_benchmark(
        const QftBenchmarkOptions& options = {});

    [[nodiscard]] std::string format_qft_benchmark_result(const QftBenchmarkResult& result);

    [[nodiscard]] std::string export_qft_benchmark_csv(
        const std::vector<QftBenchmarkResult>& results,
        const std::string& file_path = "Output/qft_benchmark.csv");
}
