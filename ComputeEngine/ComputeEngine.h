#pragma once

#include "PerformanceMonitor/PerformanceMonitor.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace crypto
{
    enum class ComputeBackend
    {
        Auto,
        Cpu,
        Gpu,
        MultiGpu
    };

    [[nodiscard]] std::string to_string(ComputeBackend backend);

    struct ComputeOptions
    {
        ComputeBackend backend = ComputeBackend::Auto;
        int selected_gpu_index = -1;
        std::size_t cpu_thread_count = 0;
        std::size_t minimum_gpu_work_items = 4096;
    };

    struct GpuDeviceInfo
    {
        int index = -1;
        std::string name;
        std::uint64_t total_memory_bytes = 0;
        int compute_major = 0;
        int compute_minor = 0;
        int multiprocessor_count = 0;
    };

    struct ComputeExecutionReport
    {
        ComputeBackend requested_backend = ComputeBackend::Auto;
        ComputeBackend actual_backend = ComputeBackend::Cpu;
        bool used_cpu_fallback = false;
        std::size_t items_processed = 0;
        std::vector<int> gpu_device_indices;
        double wall_time_ms = 0.0;
        double process_cpu_time_ms = 0.0;
        double gpu_kernel_time_ms = 0.0;
        double gpu_transfer_time_ms = 0.0;
        double gpu_initialization_time_ms = 0.0;
        std::string detail;
    };

    struct Sha256BatchReport
    {
        ComputeExecutionReport execution;
        std::size_t messages_processed = 0;
    };

    class ComputeEngine final
    {
    public:
        explicit ComputeEngine(
            ComputeOptions options = {},
            PerformanceMonitor* performance_monitor = nullptr);

        [[nodiscard]] static std::vector<GpuDeviceInfo> discover_gpus();
        [[nodiscard]] static bool cuda_compiled() noexcept;

        // This initial kernel validates CPU/GPU execution and data distribution.
        // Algorithm-specific CUDA kernels will be added alongside each algorithm.
        [[nodiscard]] ComputeExecutionReport vector_add_u32(
            std::span<const std::uint32_t> left,
            std::span<const std::uint32_t> right,
            std::span<std::uint32_t> output) const;

        [[nodiscard]] std::vector<std::array<std::uint8_t, 32>> sha256_short_batch(
            const std::vector<std::string>& messages,
            Sha256BatchReport* report = nullptr) const;

        [[nodiscard]] const ComputeOptions& options() const noexcept;

    private:
        ComputeOptions options_;
        PerformanceMonitor* performance_monitor_ = nullptr;
    };
}
