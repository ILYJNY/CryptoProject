#pragma once

#include "../../Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto::quantum
{
    struct ExperimentResult
    {
        std::string name;
        std::string summary;
        std::string backend;
        std::size_t qubits = 0;
        std::size_t gate_count = 0;
        std::size_t operation_depth = 0;
        std::size_t state_vector_bytes = 0;
        std::size_t cpu_threads = 1U;
        std::size_t cpu_operations = 0U;
        std::size_t gpu_operations = 0U;
        std::size_t cpu_fallback_operations = 0U;
        double elapsed_ms = 0.0;
        double cpu_wall_time_ms = 0.0;
        double gpu_kernel_time_ms = 0.0;
        double gpu_transfer_time_ms = 0.0;
        double gpu_initialization_time_ms = 0.0;
        int gpu_device = -1;
        std::vector<int> gpu_devices;
        double gpu_inter_gpu_transfer_time_ms = 0.0;
        double gpu_parallel_kernel_wall_time_ms = 0.0;
        std::size_t gpu_peer_copy_count = 0U;
        std::size_t gpu_host_staged_copy_count = 0U;
        std::size_t gpu_qft_fused_stage_count = 0U;
        std::size_t gpu_qft_swap_count = 0U;
        bool gpu_pinned_host_memory_used = false;
        std::vector<double> probabilities;
        bool passed = false;
    };

    struct ShorToyResult
    {
        bool factored = false;
        std::uint32_t input_number = 0;
        std::uint32_t base = 0;
        std::uint32_t factor_a = 0;
        std::uint32_t factor_b = 0;
        std::uint32_t recovered_order = 0;
        std::size_t qubits = 0;
        std::size_t shots = 0;
        double elapsed_ms = 0.0;
        std::string backend;
        std::size_t cpu_threads = 1U;
        std::size_t cpu_operations = 0U;
        std::size_t gpu_operations = 0U;
        std::size_t cpu_fallback_operations = 0U;
        double cpu_wall_time_ms = 0.0;
        double gpu_kernel_time_ms = 0.0;
        double gpu_transfer_time_ms = 0.0;
        double gpu_initialization_time_ms = 0.0;
        int gpu_device = -1;
        std::vector<int> gpu_devices;
        double gpu_inter_gpu_transfer_time_ms = 0.0;
        double gpu_parallel_kernel_wall_time_ms = 0.0;
        std::size_t gpu_peer_copy_count = 0U;
        std::size_t gpu_host_staged_copy_count = 0U;
        std::size_t gpu_qft_fused_stage_count = 0U;
        std::size_t gpu_qft_swap_count = 0U;
        bool gpu_pinned_host_memory_used = false;
        std::string status;
    };

    [[nodiscard]] ExperimentResult run_superposition_experiment(const QuantumExecutionOptions& options = {});
    [[nodiscard]] ExperimentResult run_entanglement_experiment(const QuantumExecutionOptions& options = {});
    [[nodiscard]] ExperimentResult run_interference_experiment(const QuantumExecutionOptions& options = {});
    [[nodiscard]] ExperimentResult run_measurement_experiment(
        std::size_t shots = 1000U, const QuantumExecutionOptions& options = {});
    [[nodiscard]] ExperimentResult run_grover_experiment(
        std::size_t qubits = 3U, std::size_t target = 5U, std::size_t shots = 1024U,
        const QuantumExecutionOptions& options = {});
    [[nodiscard]] ExperimentResult run_qft_experiment(
        std::size_t qubits = 3U, const QuantumExecutionOptions& options = {});
    [[nodiscard]] ShorToyResult run_shor_toy_experiment(
        std::uint32_t number = 15U, std::uint32_t base = 2U, std::size_t shots = 1024U,
        const QuantumExecutionOptions& options = {});

    [[nodiscard]] std::string format_experiment(const ExperimentResult& result);
    [[nodiscard]] std::string format_shor_result(const ShorToyResult& result);
}
