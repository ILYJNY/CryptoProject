#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto
{
    struct PerformanceRecord
    {
        std::uint64_t run_id = 0;
        std::string stage;
        std::string backend;
        double wall_time_ms = 0.0;
        double process_cpu_time_ms = 0.0;
        std::optional<double> gpu_kernel_time_ms;
        std::optional<double> gpu_transfer_time_ms;
        std::optional<double> gpu_initialization_time_ms;
        std::string detail;
    };

    struct PerformanceSummary
    {
        std::string stage;
        std::string backend;
        std::uint64_t run_count = 0;
        double average_wall_time_ms = 0.0;
        double minimum_wall_time_ms = 0.0;
        double maximum_wall_time_ms = 0.0;
        double average_process_cpu_time_ms = 0.0;
    };

    class PerformanceMonitor final
    {
    public:
        class ScopedTimer final
        {
        public:
            ScopedTimer(PerformanceMonitor& monitor, std::string stage,
                        std::string backend, std::string detail = "");
            ScopedTimer(const ScopedTimer&) = delete;
            ScopedTimer& operator=(const ScopedTimer&) = delete;
            ScopedTimer(ScopedTimer&& other) noexcept;
            ScopedTimer& operator=(ScopedTimer&& other) noexcept;
            ~ScopedTimer() noexcept;
            void stop() noexcept;

        private:
            PerformanceMonitor* monitor_ = nullptr;
            std::string stage_;
            std::string backend_;
            std::string detail_;
            std::chrono::steady_clock::time_point wall_start_;
            std::clock_t cpu_start_ = static_cast<std::clock_t>(-1);
        };

        PerformanceMonitor() = default;

        template <typename Function>
        decltype(auto) measure(std::string_view stage, std::string_view backend,
                               Function&& function, std::string_view detail = "")
        {
            ScopedTimer timer(*this, std::string(stage), std::string(backend), std::string(detail));
            return std::invoke(std::forward<Function>(function));
        }

        void record(PerformanceRecord record);
        void record_gpu_timing(std::string stage, double kernel_time_ms,
                               double transfer_time_ms, double initialization_time_ms,
                               std::string detail = "");
        [[nodiscard]] std::vector<PerformanceRecord> records() const;
        [[nodiscard]] std::vector<PerformanceSummary> summary() const;
        void export_csv(const std::filesystem::path& file_path) const;
        void export_summary_csv(const std::filesystem::path& file_path) const;
        void clear();

    private:
        mutable std::mutex mutex_;
        std::vector<PerformanceRecord> records_;
        std::atomic<std::uint64_t> next_run_id_{1};
    };
}
