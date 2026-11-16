#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace crypto::quantum
{
    enum class QuantumBackendType
    {
        CpuSingleThread,
        CpuMultiThread,
        CudaGpu,
        CudaMultiGpu
    };

    struct QuantumExecutionOptions
    {
        QuantumBackendType backend = QuantumBackendType::CpuMultiThread;
        // 0 means hardware_concurrency() for CPU multi-thread mode.
        std::size_t cpu_threads = 0U;
        int gpu_device = 0;
        // Empty in CudaMultiGpu mode selects the largest available power-of-two device set.
        std::vector<int> gpu_devices{};
    };

    struct QuantumBackendStatistics
    {
        std::uint64_t cpu_operations = 0U;
        std::uint64_t gpu_operations = 0U;
        std::uint64_t cpu_fallback_operations = 0U;
        double cpu_wall_time_ms = 0.0;
        double gpu_kernel_time_ms = 0.0;
        double gpu_transfer_time_ms = 0.0;
        double gpu_initialization_time_ms = 0.0;
        std::size_t cpu_threads_used = 1U;
        int gpu_device_used = -1;
        std::vector<int> gpu_devices_used{};
        double gpu_inter_gpu_transfer_time_ms = 0.0;
        double gpu_parallel_kernel_wall_time_ms = 0.0;
        std::uint64_t gpu_peer_copy_count = 0U;
        std::uint64_t gpu_host_staged_copy_count = 0U;
        std::uint64_t gpu_qft_fused_stage_count = 0U;
        std::uint64_t gpu_qft_swap_count = 0U;
        bool gpu_pinned_host_memory_used = false;
    };
}
