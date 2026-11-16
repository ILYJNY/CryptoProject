#include "PerformanceMonitor/PerformanceMonitor.h"
#include "ErrorHandling/CryptoException.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <tuple>

namespace crypto
{
    namespace
    {
        [[nodiscard]] std::string csv_escape(const std::string& value)
        {
            if (value.find_first_of(",\"\r\n") == std::string::npos) return value;
            std::string result = "\"";
            for (const char c : value)
            {
                if (c == '\"') result += "\"\"";
                else result += c;
            }
            result += '\"';
            return result;
        }

        void prepare_directory(const std::filesystem::path& file_path)
        {
            if (file_path.has_parent_path()) std::filesystem::create_directories(file_path.parent_path());
        }

        [[nodiscard]] std::string optional_value(const std::optional<double>& value)
        {
            if (!value.has_value()) return {};
            std::ostringstream stream;
            stream << std::setprecision(12) << *value;
            return stream.str();
        }
    }

    PerformanceMonitor::ScopedTimer::ScopedTimer(
        PerformanceMonitor& monitor, std::string stage,
        std::string backend, std::string detail)
        : monitor_(&monitor), stage_(std::move(stage)), backend_(std::move(backend)),
          detail_(std::move(detail)), wall_start_(std::chrono::steady_clock::now()),
          cpu_start_(std::clock())
    {
    }

    PerformanceMonitor::ScopedTimer::ScopedTimer(ScopedTimer&& other) noexcept
        : monitor_(std::exchange(other.monitor_, nullptr)),
          stage_(std::move(other.stage_)), backend_(std::move(other.backend_)),
          detail_(std::move(other.detail_)), wall_start_(other.wall_start_),
          cpu_start_(other.cpu_start_)
    {
    }

    PerformanceMonitor::ScopedTimer&
    PerformanceMonitor::ScopedTimer::operator=(ScopedTimer&& other) noexcept
    {
        if (this != &other)
        {
            stop();
            monitor_ = std::exchange(other.monitor_, nullptr);
            stage_ = std::move(other.stage_);
            backend_ = std::move(other.backend_);
            detail_ = std::move(other.detail_);
            wall_start_ = other.wall_start_;
            cpu_start_ = other.cpu_start_;
        }
        return *this;
    }

    PerformanceMonitor::ScopedTimer::~ScopedTimer() noexcept { stop(); }

    void PerformanceMonitor::ScopedTimer::stop() noexcept
    {
        if (monitor_ == nullptr) return;
        try
        {
            const auto wall_end = std::chrono::steady_clock::now();
            const auto wall_ms = std::chrono::duration<double, std::milli>(wall_end - wall_start_).count();
            double cpu_ms = 0.0;
            const std::clock_t cpu_end = std::clock();
            if (cpu_start_ != static_cast<std::clock_t>(-1) && cpu_end != static_cast<std::clock_t>(-1))
                cpu_ms = static_cast<double>(cpu_end - cpu_start_) * 1000.0 / static_cast<double>(CLOCKS_PER_SEC);

            PerformanceRecord item;
            item.run_id = monitor_->next_run_id_.fetch_add(1);
            item.stage = std::move(stage_);
            item.backend = std::move(backend_);
            item.wall_time_ms = wall_ms;
            item.process_cpu_time_ms = cpu_ms;
            item.detail = std::move(detail_);
            monitor_->record(std::move(item));
        }
        catch (...)
        {
            // A scoped timer must never throw from its destructor.
        }
        monitor_ = nullptr;
    }

    void PerformanceMonitor::record(PerformanceRecord record)
    {
        std::scoped_lock lock(mutex_);
        if (record.run_id == 0)
        {
            record.run_id = next_run_id_.fetch_add(1);
        }
        records_.push_back(std::move(record));
    }

    void PerformanceMonitor::record_gpu_timing(
        std::string stage, const double kernel_time_ms,
        const double transfer_time_ms, const double initialization_time_ms,
        std::string detail)
    {
        PerformanceRecord item;
        item.run_id = next_run_id_.fetch_add(1);
        item.stage = std::move(stage);
        item.backend = "GPU";
        item.gpu_kernel_time_ms = kernel_time_ms;
        item.gpu_transfer_time_ms = transfer_time_ms;
        item.gpu_initialization_time_ms = initialization_time_ms;
        item.detail = std::move(detail);
        record(std::move(item));
    }

    std::vector<PerformanceRecord> PerformanceMonitor::records() const
    {
        std::scoped_lock lock(mutex_);
        return records_;
    }

    std::vector<PerformanceSummary> PerformanceMonitor::summary() const
    {
        using Key = std::pair<std::string, std::string>;
        struct Accumulator
        {
            std::uint64_t count = 0;
            double sum = 0.0;
            double minimum = 0.0;
            double maximum = 0.0;
            double cpu_sum = 0.0;
        };

        std::map<Key, Accumulator> grouped;
        for (const auto& item : records())
        {
            auto& acc = grouped[{item.stage, item.backend}];
            if (acc.count == 0) { acc.minimum = item.wall_time_ms; acc.maximum = item.wall_time_ms; }
            else
            {
                acc.minimum = std::min(acc.minimum, item.wall_time_ms);
                acc.maximum = std::max(acc.maximum, item.wall_time_ms);
            }
            ++acc.count;
            acc.sum += item.wall_time_ms;
            acc.cpu_sum += item.process_cpu_time_ms;
        }

        std::vector<PerformanceSummary> result;
        result.reserve(grouped.size());
        for (const auto& [key, acc] : grouped)
        {
            PerformanceSummary item;
            item.stage = key.first;
            item.backend = key.second;
            item.run_count = acc.count;
            item.average_wall_time_ms = acc.sum / static_cast<double>(acc.count);
            item.minimum_wall_time_ms = acc.minimum;
            item.maximum_wall_time_ms = acc.maximum;
            item.average_process_cpu_time_ms = acc.cpu_sum / static_cast<double>(acc.count);
            result.push_back(std::move(item));
        }
        return result;
    }

    void PerformanceMonitor::export_csv(const std::filesystem::path& file_path) const
    {
        prepare_directory(file_path);
        std::ofstream output(file_path, std::ios::out | std::ios::trunc);
        if (!output) raise_error(ErrorCode::IoError, "Unable to create the performance CSV file.");
        output << "run_id,stage,backend,wall_time_ms,process_cpu_time_ms,gpu_kernel_time_ms,gpu_transfer_time_ms,gpu_initialization_time_ms,detail\n";
        for (const auto& item : records())
        {
            output << item.run_id << ',' << csv_escape(item.stage) << ',' << csv_escape(item.backend) << ','
                   << std::setprecision(12) << item.wall_time_ms << ',' << item.process_cpu_time_ms << ','
                   << optional_value(item.gpu_kernel_time_ms) << ',' << optional_value(item.gpu_transfer_time_ms) << ','
                   << optional_value(item.gpu_initialization_time_ms) << ',' << csv_escape(item.detail) << '\n';
        }
        if (!output) raise_error(ErrorCode::IoError, "Writing the performance CSV file failed.");
    }

    void PerformanceMonitor::export_summary_csv(const std::filesystem::path& file_path) const
    {
        prepare_directory(file_path);
        std::ofstream output(file_path, std::ios::out | std::ios::trunc);
        if (!output) raise_error(ErrorCode::IoError, "Unable to create the performance summary CSV file.");
        output << "stage,backend,run_count,average_wall_time_ms,minimum_wall_time_ms,maximum_wall_time_ms,average_process_cpu_time_ms\n";
        for (const auto& item : summary())
        {
            output << csv_escape(item.stage) << ',' << csv_escape(item.backend) << ',' << item.run_count << ','
                   << std::setprecision(12) << item.average_wall_time_ms << ',' << item.minimum_wall_time_ms << ','
                   << item.maximum_wall_time_ms << ',' << item.average_process_cpu_time_ms << '\n';
        }
        if (!output) raise_error(ErrorCode::IoError, "Writing the performance summary CSV file failed.");
    }

    void PerformanceMonitor::clear()
    {
        std::scoped_lock lock(mutex_);
        records_.clear();
    }
}
